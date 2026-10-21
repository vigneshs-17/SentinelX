"""Audit findings N1-N8: ingest-time retention, read-only API, login lockout, session/audit/triage housekeeping."""

import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from scapy.all import wrpcap

import main as main_mod
from backend import accounts, auth, housekeeping
from backend import api as api_mod
from capture.sensor import Sensor
from database.database import (
    close_database,
    get_connection,
    get_database_path,
    get_readonly_connection,
    insert_alert,
    prune_alerts,
)
from database.migrations import apply_migrations, migration_1, migration_2, migration_3, migration_4, migration_5
from eval.scenarios import generate_scenario
from logs.sinks import CompositeSink, SqliteSink
from tests.support import authed_client

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def alert(**kw):
    base = {"threat_type": "PORT_SCAN", "severity": "HIGH", "source_ip": "10.0.0.5", "detected_at": iso(NOW)}
    base.update(kw)
    return base


def one(sql, params=()):
    conn = get_connection()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


# ------------------------------------------------------------------ N1: retention by ingest time


def test_migration_6_upgrades_a_version_5_database_and_keeps_every_row(tmp_path):
    path = tmp_path / "v5.db"
    conn = sqlite3.connect(path)
    migration_1(conn)
    migration_2(conn)
    migration_3(conn)
    migration_4(conn)
    migration_5(conn)
    conn.execute("PRAGMA user_version = 5")
    conn.execute(
        "INSERT INTO alerts (timestamp, detected_at, threat_type, severity) VALUES (?, ?, 'PORT_SCAN', 'HIGH')",
        ("2023-05-01T00:00:00+00:00", "2023-05-01T00:00:00+00:00"),
    )
    conn.commit()
    assert "ingested_at" not in {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert apply_migrations(conn) == 6
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 6
    row = conn.execute("SELECT detected_at, ingested_at FROM alerts").fetchone()
    assert row[0] == "2023-05-01T00:00:00+00:00"  # event time untouched
    assert row[1] is not None and row[1] > "2026"  # stamped with the upgrade time, so it ages from the upgrade
    assert apply_migrations(conn) == 6  # idempotent
    conn.close()


def test_insert_stamps_wall_clock_ingest_time_not_event_time():
    insert_alert(alert(detected_at="2023-01-01T00:00:00+00:00"))
    detected, ingested = one("SELECT detected_at, ingested_at FROM alerts")
    assert detected.startswith("2023-01-01")
    assert abs((datetime.fromisoformat(ingested) - datetime.now(UTC)).total_seconds()) < 60


def test_prune_uses_ingest_time_so_old_event_time_alone_deletes_nothing():
    insert_alert(alert(detected_at="2023-01-01T00:00:00+00:00"))  # ancient event, ingested just now
    insert_alert(alert(ingested_at=iso(NOW - timedelta(days=40)), source_ip="10.9.9.9"))  # genuinely old row
    assert prune_alerts(iso(NOW - timedelta(days=30))) == 1
    assert one("SELECT COUNT(*) FROM alerts")[0] == 1
    assert one("SELECT source_ip FROM alerts")[0] == "10.0.0.5"


def test_replaying_a_2023_capture_three_times_with_retention_on_keeps_every_alert(tmp_path):
    packets = generate_scenario("fast_vertical_scan", base_ts=datetime(2023, 3, 1, tzinfo=UTC).timestamp())[0]
    pcap = tmp_path / "old.pcap"
    wrpcap(str(pcap), packets)
    counts = []
    for _ in range(3):
        sensor = Sensor(
            sink=CompositeSink([SqliteSink()]), status_interval=3600, retention_days=30, retention_interval=0.01
        )
        sensor.run_replay(str(pcap))
        assert not [t for t in sensor._threads if "retention" in t.name]
        counts.append(one("SELECT COUNT(*) FROM alerts")[0])
    assert counts[0] >= 1 and counts == [counts[0] * i for i in (1, 2, 3)]  # nothing was deleted between runs
    assert one("SELECT MAX(detected_at) FROM alerts")[0] < "2024"  # they really are 2023 event times


def test_live_start_runs_retention_thread_and_replay_does_not():
    live = Sensor(sink=CompositeSink([]), status_interval=3600, retention_interval=3600)
    live.start()
    try:
        assert {t.name for t in live._threads} == {"Sensor-heartbeat", "Sensor-retention"}
    finally:
        live.stop()
    replay = Sensor(sink=CompositeSink([]), status_interval=3600, retention_interval=3600)
    replay.start(retention=False)
    try:
        assert {t.name for t in replay._threads} == {"Sensor-heartbeat"}
    finally:
        replay.stop()


# ------------------------------------------------------------------ N2: read-only volume


@contextmanager
def locked_dir(path: Path):
    """Make a directory refuse new files (what a read-only Docker volume does); restore on exit."""
    if sys.platform == "win32":
        user = os.environ["USERNAME"]
        subprocess.run(["icacls", str(path), "/deny", f"{user}:(WD,AD,DC)"], check=True, capture_output=True)
        try:
            yield
        finally:
            subprocess.run(["icacls", str(path), "/remove:d", user], check=True, capture_output=True)
    else:
        path.chmod(0o555)
        try:
            yield
        finally:
            path.chmod(0o755)


def readonly_copy_of_cleanly_closed_wal_db(tmp_path: Path) -> Path:
    """Copy alerts.db after the writer closed (the sensor's clean shutdown removes -wal and -shm)."""
    insert_alert(alert())
    close_database()
    src = get_database_path()
    # A clean close checkpoints and deletes -wal/-shm; make sure the copy has none, like the shared volume would.
    conn = sqlite3.connect(src)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    vol = tmp_path / "rovol"
    vol.mkdir()
    dest = vol / "alerts.db"
    shutil.copy(src, dest)
    for suffix in ("-wal", "-shm"):
        Path(f"{dest}{suffix}").unlink(missing_ok=True)
    dest.chmod(0o444)
    return dest


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores directory permissions, so chmod cannot make the directory read-only",
)
def test_old_readonly_open_failed_on_a_readonly_copy_and_the_new_one_reads_but_cannot_write(tmp_path):
    dest = readonly_copy_of_cleanly_closed_wal_db(tmp_path)
    with locked_dir(dest.parent):
        old = sqlite3.connect(f"{dest.as_uri()}?mode=ro", uri=True)  # the pre-fix open
        # Windows reports "unable to open database file", Linux "attempt to write a readonly database".
        with pytest.raises(sqlite3.OperationalError, match="unable to open|readonly database"):
            old.execute("SELECT COUNT(*) FROM alerts").fetchone()
        old.close()

        conn = get_readonly_connection(dest)
        try:
            assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
            for stmt in (
                "DELETE FROM alerts",
                "INSERT INTO alerts (timestamp, threat_type, severity) VALUES ('t', 'x', 'y')",
                "UPDATE alerts SET severity = 'LOW'",
                "DROP TABLE alerts",
            ):
                with pytest.raises(sqlite3.OperationalError):
                    conn.execute(stmt)
                    conn.commit()
        finally:
            conn.close()
    assert not Path(f"{dest}-wal").exists() and not Path(f"{dest}-shm").exists()
    dest.chmod(0o666)
    check = sqlite3.connect(dest)
    assert check.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1  # file itself unchanged
    check.close()


def test_health_reads_alerts_on_a_readonly_volume_and_reports_degraded_when_it_cannot(tmp_path, monkeypatch):
    dest = readonly_copy_of_cleanly_closed_wal_db(tmp_path)
    monkeypatch.setenv("SENTINELX_DB_PATH", str(dest))
    client = api_mod.app.test_client()
    with locked_dir(dest.parent):
        ok = client.get("/health")
        assert ok.status_code == 200 and ok.get_json()["status"] == "healthy"
        assert authed_client(api_mod.app).get("/api/v1/alerts").status_code == 200  # a real endpoint works too
    dest.chmod(0o666)
    dest.unlink()
    bad = client.get("/health")
    assert bad.status_code == 503 and bad.get_json()["status"] == "degraded"


def test_health_is_degraded_when_the_alerts_table_cannot_be_read(tmp_path, monkeypatch):
    broken = tmp_path / "empty.db"
    sqlite3.connect(broken).close()  # opens fine, has no alerts table: an open-only check would say healthy
    monkeypatch.setenv("SENTINELX_DB_PATH", str(broken))
    resp = api_mod.app.test_client().get("/health")
    assert resp.status_code == 503 and resp.get_json()["status"] == "degraded"


def test_immutable_fallback_is_not_used_while_a_wal_file_exists(tmp_path):
    conn = sqlite3.connect(tmp_path / "live.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (x)")
    conn.commit()  # connection stays open: -wal exists, so a writer may be active
    assert Path(f"{tmp_path / 'live.db'}-wal").exists()
    ro = get_readonly_connection(tmp_path / "live.db")
    ro.close()
    conn.close()


# ------------------------------------------------------------------ N3: lockout scope, X-Forwarded-For warning


def test_failures_from_ip_a_do_not_block_the_correct_password_from_ip_b():
    accounts.create_user("victim", "a long enough password", "viewer")
    client = api_mod.app.test_client()

    def login(pw, ip):
        return client.post("/login", json={"username": "victim", "password": pw}, environ_overrides={"REMOTE_ADDR": ip})

    for _ in range(auth.LOGIN_MAX_FAILURES):
        assert login("wrong password here", "198.51.100.1").status_code == 401
    assert login("a long enough password", "198.51.100.1").status_code == 429  # A is locked for this user
    assert login("a long enough password", "198.51.100.2").status_code == 200  # B is not
    assert "Too many attempts" in login("x", "198.51.100.1").get_json()["message"]


def test_xff_without_trusted_proxies_logs_one_warning(monkeypatch, caplog):
    monkeypatch.setattr(auth, "TRUSTED_PROXIES", [])
    monkeypatch.setattr(auth, "_xff_warned", False)
    caplog.set_level(logging.WARNING, logger="sentinelx.auth")
    client = api_mod.app.test_client()
    for _ in range(3):
        client.get("/health", headers={"X-Forwarded-For": "203.0.113.5"})
    # /health does not call client_ip(); an authenticated API call does (rate limit identity).
    for _ in range(3):
        client.get("/api/v1/stats", headers={"X-Forwarded-For": "203.0.113.5"})
    warnings = [r for r in caplog.records if "X-Forwarded-For" in r.getMessage()]
    assert len(warnings) == 1 and "SENTINELX_TRUSTED_PROXIES" in warnings[0].getMessage()


# ------------------------------------------------------------------ N6: housekeeping and audit retention


def test_expired_sessions_are_purged_without_anyone_presenting_them(monkeypatch):
    uid = accounts.create_user("sess-user", "a long enough password", "viewer")
    t = [1_800_000_000.0]
    monkeypatch.setattr(accounts, "now", lambda: t[0])
    accounts.create_session(uid, "192.0.2.1")
    t[0] += 10
    accounts.create_session(uid, "192.0.2.1")
    assert accounts.purge_expired_sessions() == 0
    t[0] += accounts.SESSION_IDLE_SECONDS - 5  # first session idle too long, second just inside
    assert accounts.purge_expired_sessions() == 1
    t[0] += accounts.SESSION_ABSOLUTE_SECONDS  # everything past the absolute limit
    assert accounts.purge_expired_sessions() == 1
    with accounts.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_audit_prune_deletes_only_old_rows_and_the_append_only_trigger_survives(monkeypatch):
    base = datetime(2026, 10, 20, tzinfo=UTC).timestamp()
    monkeypatch.setattr(accounts, "now", lambda: base - 400 * 86400)
    accounts.audit("test.old", "tester")
    monkeypatch.setattr(accounts, "now", lambda: base)
    accounts.audit("test.new", "tester")
    assert accounts.prune_audit(0) == 0  # 0 = keep forever
    assert accounts.prune_audit(365) == 1
    actions = [r["action"] for r in accounts.query_audit()]
    assert "test.old" not in actions and "test.new" in actions and "audit.prune" in actions
    with accounts.db() as conn:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM audit_log")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE audit_log SET actor = 'x'")


def test_audit_log_is_not_deletable_through_normal_paths():
    accounts.audit("test.keep", "tester")
    with accounts.db() as conn:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM audit_log WHERE action = 'test.keep'")


def test_db_prune_audit_cli_respects_the_setting(capsys, monkeypatch):
    accounts.audit("test.cli", "tester")
    monkeypatch.setattr("config.settings.AUDIT_RETENTION_DAYS", 0)
    main_mod.handle_db(main_mod.parse_arguments(["db", "prune-audit"]))
    assert "kept forever" in capsys.readouterr().out
    monkeypatch.setattr("config.settings.AUDIT_RETENTION_DAYS", 365)
    main_mod.handle_db(main_mod.parse_arguments(["db", "prune-audit"]))
    assert "Deleted 0 audit rows" in capsys.readouterr().out


def test_triage_rows_of_alerts_removed_by_retention_are_deleted():
    insert_alert(alert(ingested_at=iso(NOW - timedelta(days=60)), source_ip="10.5.5.1"))
    insert_alert(alert(source_ip="10.5.5.2"))
    conn = get_connection()
    try:
        old_id, new_id = (r[0] for r in conn.execute("SELECT id FROM alerts ORDER BY id").fetchall())
    finally:
        conn.close()
    for alert_id in (old_id, new_id):
        accounts.set_triage(alert_id, {"status": "acknowledged", "assignee": None, "note": None}, "user:t", None)
    prune_alerts(iso(NOW - timedelta(days=30)))
    assert housekeeping.run_once()["triage"] == 1
    assert accounts.get_triage(old_id) is None and accounts.get_triage(new_id) is not None


def test_prune_cli_also_removes_orphan_triage(capsys):
    insert_alert(alert(ingested_at=iso(datetime.now(UTC) - timedelta(days=90))))
    alert_id = one("SELECT id FROM alerts")[0]
    accounts.set_triage(alert_id, {"status": "resolved_fp", "assignee": None, "note": "x"}, "user:t", None)
    main_mod.handle_db(main_mod.parse_arguments(["db", "prune", "--older-than", "30d"]))
    out = capsys.readouterr().out
    assert "Deleted 1 alerts" in out and "Deleted 1 triage rows" in out
    assert accounts.get_triage(alert_id) is None


def test_housekeeping_survives_a_locked_app_database(monkeypatch, caplog):
    def locked():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(accounts, "get_app_connection", locked)
    caplog.set_level(logging.WARNING, logger="sentinelx.housekeeping")
    assert housekeeping.run_once() == {"sessions": 0, "triage": 0}
    assert "session purge failed" in caplog.text and "triage cleanup failed" in caplog.text


# ------------------------------------------------------------------ N7: app.db errors are not "sensor database" errors


def test_app_db_lock_is_reported_as_application_database_not_sensor_database(monkeypatch):
    client = authed_client(api_mod.app)

    def locked():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(accounts, "get_app_connection", locked)
    resp = client.get("/api/v1/stats")
    body = resp.get_json()
    assert resp.status_code == 503 and "application database" in body["message"].lower()
    assert "sensor database" not in body["message"].lower() and resp.headers["Retry-After"] == "1"


def test_alerts_db_failure_still_says_sensor_database(monkeypatch):
    client = authed_client(api_mod.app)

    def broken():
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(api_mod, "get_readonly_connection", broken)
    body = client.get("/api/v1/sensor/status").get_json()
    assert "sensor database" in body["message"].lower()


# ------------------------------------------------------------------ N4/N5/docs honesty


ROOT = Path(__file__).resolve().parent.parent


def test_container_files_grant_only_net_raw():
    for name in ("docker-compose.yml", "Dockerfile"):
        text = (ROOT / name).read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        assert "net_admin" not in code.lower(), name


def test_docs_state_signature_scope_and_drop_unsupported_claims():
    design = (ROOT / "docs" / "DESIGN.md").read_text(encoding="utf-8")
    assert "protection against file tampering" in design and "honest evaluation" in design
    for claim in ("~219 MB", "Measured: no speed-up", "is enough for the networks this targets"):
        assert claim not in design
    assert "15 ports" not in (ROOT / "eval" / "README.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "min-max of 3 runs; machine-dependent" in readme
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for d in ("D6", "D8", "D9", "D14", "D15"):
        assert f"| {d} |" in changelog and "meaning not recorded" not in changelog


def test_unused_settings_are_gone_from_code_and_docs():
    gone = ("SENTINELX_MAX_TRACKED_ENTRIES", "SENTINELX_MODE", "SENTINELX_PCAP_PATH", "SENTINELX_API_DEBUG")
    for path in ("config/settings.py", "docs/OPERATIONS.md", "scripts/gen_config_docs.py"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert not any(re.search(rf"{name}", text) for name in gone), path


def test_live_capture_callback_returns_none_so_scapy_prints_nothing_per_packet(monkeypatch):
    """Scapy's sniff() prints the prn return value; enqueue() returns a bool, which printed "True" per packet."""
    from capture import packet_capture

    seen: dict[str, object] = {}

    class FakePipeline:
        maxsize = 1

        def __init__(self):
            self.enqueued = []

        def enqueue(self, packet):
            self.enqueued.append(packet)
            return True

        def start(self):
            pass

        def stop(self, drain=True):
            pass

        def get_snapshot(self):
            return {}

    def fake_sniff(**kwargs):
        seen.update(kwargs)

    pipe = FakePipeline()
    monkeypatch.setattr(packet_capture, "sniff", fake_sniff)
    packet_capture.start_capture(pipeline_instance=pipe)
    callback = seen["prn"]
    assert callback("pkt") is None
    assert pipe.enqueued == ["pkt"]


# ------------------------------------------------------------------ endpoint rename (ad blockers block "metrics")


def test_sensor_endpoints_exist_and_the_old_metrics_paths_are_gone():
    client = authed_client(api_mod.app)
    assert client.get("/api/v1/sensor/status").status_code == 200
    assert client.get("/api/v1/sensor/history").status_code == 200
    for old in ("/api/v1/metrics", "/api/v1/metrics/history"):
        assert client.get(old).status_code == 404  # no alias
    assert not [r for r in api_mod.app.url_map.iter_rules() if "metrics" in r.rule]
