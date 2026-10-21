"""Step 6a: process split, waitress serving, read-only API, retention, sensor heartbeat, alert sinks, webhook."""

import json
import logging
import sqlite3
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.all import wrpcap

import main as main_mod
from backend import accounts
from backend import api as api_mod
from capture.sensor import Sensor
from database.app_db import get_app_connection, initialize_app_database
from database.database import (
    close_database,
    fetch_latest_sensor_status,
    get_connection,
    get_readonly_connection,
    insert_alert,
    insert_sensor_status,
    parse_age,
    prune_alerts,
)
from eval.scenarios import generate_scenario
from logs.sinks import CompositeSink, JsonlSink, SqliteSink, WebhookSink, build_sink_from_env, webhook_payload
from tests.support import authed_client


def qone(sql: str, params: tuple = ()):
    """Run one query on a throwaway connection and close it (Windows keeps open handles locked)."""
    conn = get_connection()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def qall(sql: str, params: tuple = ()):
    conn = get_connection()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)


def alert(**kw):
    base = {
        "threat_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "severity": "HIGH",
        "confidence": 0.9,
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.9",
        "protocol": "TCP",
        "detected_at": iso(NOW),
        "timestamp": iso(NOW),
        "first_seen": NOW.timestamp(),
        "last_seen": NOW.timestamp(),
        "message": "m",
        "sensor_id": "sensor-1",
    }
    base.update(kw)
    base.setdefault("ingested_at", base["detected_at"])  # retention ages rows by ingest time (N1)
    return base


def status_row(last_seen: datetime, **kw):
    row = {
        "sensor_id": "sensor-1",
        "last_seen": iso(last_seen),
        "received": 100,
        "dropped": 2,
        "queue_depth": 3,
        "pps_10s": 12.5,
        "state_size": 40,
        "evictions": 1,
        "webhook_failures": 0,
    }
    row.update(kw)
    return row


# ------------------------------------------------------------------ process split / serving


def test_api_connection_is_read_only_and_never_creates_the_database(tmp_path):
    db = tmp_path / "alerts.db"
    with pytest.raises(sqlite3.OperationalError):
        get_readonly_connection(db)  # missing file is not created
    assert not db.exists()

    insert_alert(alert())  # sensor-side write into the fixture database
    ro = get_readonly_connection()
    assert ro.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    for stmt in (
        "DELETE FROM alerts",
        "INSERT INTO alerts (timestamp, threat_type, severity) VALUES ('t','x','y')",
        "DROP TABLE alerts",
    ):
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ro.execute(stmt)
    ro.close()


def test_api_module_does_not_initialize_or_write_the_alert_database(monkeypatch, tmp_path):
    """Regression for the old import-time initialize_database(): the API must not create or migrate alerts.db."""
    import importlib

    target = tmp_path / "never_created.db"
    monkeypatch.setenv("SENTINELX_DB_PATH", str(target))
    importlib.reload(api_mod)
    assert not target.exists()
    resp = authed_client(api_mod.app).get("/api/v1/alerts")
    assert resp.status_code == 503 and not target.exists()


def test_run_requires_dev_flag(capsys):
    args = main_mod.parse_arguments(["run"])
    with pytest.raises(SystemExit) as exc:
        main_mod.handle_run(args)
    assert exc.value.code == 2 and "--dev" in capsys.readouterr().out


def test_api_command_refuses_to_start_without_sensor_database(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("SENTINELX_DB_PATH", str(tmp_path / "missing.db"))
    with patch("waitress.serve") as serve:
        with pytest.raises(SystemExit) as exc:
            main_mod.handle_api(main_mod.parse_arguments(["api"]))
    assert exc.value.code == 2 and "sensor" in capsys.readouterr().out
    serve.assert_not_called()


def test_api_command_serves_with_waitress_not_the_flask_dev_server(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELX_APP_DB_PATH", str(tmp_path / "app.db"))
    initialize_app_database()
    accounts.create_user("admin-one", "correct horse battery", "admin")
    # The housekeeping loop is a real thread; started here it would outlive the test and touch the temp dir.
    with (
        patch("waitress.serve") as serve,
        patch.object(api_mod.app, "run") as flask_run,
        patch("backend.housekeeping.start") as housekeeping_start,
    ):
        main_mod.handle_api(main_mod.parse_arguments(["api"]))
    housekeeping_start.assert_called_once()
    serve.assert_called_once()
    assert serve.call_args.args[0] is api_mod.app and serve.call_args.kwargs["threads"] >= 1
    flask_run.assert_not_called()
    assert (tmp_path / "app.db").exists()


def test_waitress_actually_serves_health_and_metrics():
    import waitress

    server = waitress.create_server(api_mod.app, host="127.0.0.1", port=0, threads=2)
    port = server.effective_port
    _, key = accounts.create_api_key("waitress-test", "viewer")
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as r:  # noqa: S310
            assert r.status == 200 and json.loads(r.read())["status"] == "healthy"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/v1/sensor/status", headers={"Authorization": f"Bearer {key}"}
        )  # noqa: S310
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
            assert json.loads(r.read())["sensor_online"] is False
    finally:
        server.close()
        t.join(timeout=5)


def test_app_db_is_separate_idempotent_and_versioned(tmp_path):
    path = tmp_path / "app.db"
    assert initialize_app_database(path) == initialize_app_database(path) >= 1
    conn = get_app_connection(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] >= 1
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='app_meta'").fetchone()
    conn.close()
    assert path.name != Path(qone("PRAGMA database_list")[2]).name


# ------------------------------------------------------------------ sensor: D2 / D4 and housekeeping


def test_sensor_replay_creates_database_and_records_alerts_on_its_own_pipeline(tmp_path, monkeypatch):
    """D2 + D4: fresh data dir -> sensor creates the schema; alerts_generated counts on the running pipeline."""
    monkeypatch.setenv("SENTINELX_DB_PATH", str(tmp_path / "fresh" / "alerts.db"))
    monkeypatch.setenv("SENTINELX_ALERT_LOG", str(tmp_path / "fresh" / "alerts.jsonl"))
    close_database()
    pcap = tmp_path / "scan.pcap"
    wrpcap(str(pcap), generate_scenario("fast_vertical_scan")[0])
    sensor = Sensor(sink=CompositeSink([JsonlSink(), SqliteSink()]), status_interval=3600, retention_interval=3600)
    snap = sensor.run_replay(str(pcap))
    assert snap["packets_processed"] == 30 and snap["alerts_generated"] >= 1
    conn = get_connection(tmp_path / "fresh" / "alerts.db")
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE threat_type='PORT_SCAN'").fetchone()[0] >= 1
    assert fetch_latest_sensor_status(conn) is not None  # start and stop each wrote a heartbeat
    conn.close()


def test_heartbeat_row_reports_pipeline_and_engine_numbers():
    ticks = iter([0.0, 10.0])
    sensor = Sensor(sink=CompositeSink([]), utcnow=lambda: NOW, monotonic=lambda: next(ticks))
    for pkt in generate_scenario("fast_vertical_scan")[0]:
        sensor.pipeline.enqueue(pkt)
    sensor.pipeline.start()
    sensor.pipeline.stop(drain=True)
    status = sensor.write_status()
    assert status["received"] == 30 and status["dropped"] == 0
    assert status["pps_10s"] == pytest.approx(3.0)  # 30 processed packets over 10 s
    assert status["state_size"] > 0 and status["evictions"] == 0 and status["last_seen"] == iso(NOW)
    conn = get_connection()
    row = fetch_latest_sensor_status(conn)
    conn.close()
    assert row is not None and row["received"] == 30


def test_sensor_threads_write_heartbeats_and_stop_cleanly():
    sensor = Sensor(sink=CompositeSink([]), status_interval=0.05, retention_days=0, retention_interval=3600)
    sensor.start()
    deadline = time.time() + 5
    conn = get_connection()
    while time.time() < deadline and conn.execute("SELECT COUNT(*) FROM sensor_status").fetchone()[0] < 3:
        time.sleep(0.05)
    sensor.stop()
    assert conn.execute("SELECT COUNT(*) FROM sensor_status").fetchone()[0] >= 3
    conn.close()
    assert not sensor._threads


# ------------------------------------------------------------------ retention


def test_parse_age():
    assert parse_age("30d") == timedelta(days=30) and parse_age("12h") == timedelta(hours=12)
    for bad in ("", "0d", "-1d", "10", "5m", "d", "1.5d"):
        with pytest.raises(ValueError):
            parse_age(bad)


def test_prune_deletes_only_older_alerts():
    for days in (40, 31, 29, 1):
        insert_alert(alert(detected_at=iso(NOW - timedelta(days=days)), source_ip=f"10.1.0.{days}"))
    cutoff = iso(NOW - timedelta(days=30))
    assert prune_alerts(cutoff) == 2
    remaining = {r[0] for r in qall("SELECT source_ip FROM alerts")}
    assert remaining == {"10.1.0.29", "10.1.0.1"}
    assert prune_alerts(cutoff) == 0


def test_db_prune_cli(capsys):
    old = datetime.now(UTC) - timedelta(days=45)
    insert_alert(alert(detected_at=iso(old)))
    insert_alert(alert(detected_at=iso(datetime.now(UTC))))
    main_mod.handle_db(main_mod.parse_arguments(["db", "prune", "--older-than", "30d"]))
    assert "Deleted 1 alerts" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        main_mod.handle_db(main_mod.parse_arguments(["db", "prune", "--older-than", "soon"]))
    assert exc.value.code == 2


def test_sensor_retention_prunes_alerts_and_old_heartbeats_and_zero_disables():
    insert_alert(alert(detected_at=iso(NOW - timedelta(days=40))))
    insert_alert(alert(detected_at=iso(NOW - timedelta(days=2)), source_ip="10.2.0.2"))
    insert_sensor_status(status_row(NOW - timedelta(hours=100)))
    insert_sensor_status(status_row(NOW - timedelta(hours=1)))

    disabled = Sensor(sink=CompositeSink([]), retention_days=0, utcnow=lambda: NOW)
    assert disabled.prune_now() == 0
    conn = get_connection()
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2  # alerts untouched when disabled
    assert conn.execute("SELECT COUNT(*) FROM sensor_status").fetchone()[0] == 1  # heartbeats still bounded

    enabled = Sensor(sink=CompositeSink([]), retention_days=30, utcnow=lambda: NOW)
    assert enabled.prune_now() == 1
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    conn.close()


# ------------------------------------------------------------------ /api/v1/sensor/status


def test_metrics_online_offline_and_never_reported(monkeypatch):
    client = authed_client(api_mod.app)
    body = client.get("/api/v1/sensor/status").get_json()
    assert body["sensor_online"] is False and body["last_seen"] is None

    insert_sensor_status(status_row(NOW))
    monkeypatch.setattr(api_mod, "utcnow", lambda: NOW + timedelta(seconds=29))
    online = client.get("/api/v1/sensor/status").get_json()
    assert online["sensor_online"] is True and online["received"] == 100 and online["pps_10s"] == 12.5
    assert "id" not in online and online["age_seconds"] == 29.0

    monkeypatch.setattr(api_mod, "utcnow", lambda: NOW + timedelta(seconds=31))
    assert client.get("/api/v1/sensor/status").get_json()["sensor_online"] is False


# ------------------------------------------------------------------ sinks


class Boom(SqliteSink):
    def emit(self, record):
        raise OSError("disk full")


def test_composite_sink_isolates_failures_and_normalizes_once(tmp_path):
    jsonl = JsonlSink()
    composite = CompositeSink([Boom(), jsonl, SqliteSink()])
    record = composite({"threat_type": "PORT_SCAN", "severity": "HIGH", "source_ip": "9.9.9.9"})  # no timestamps
    assert record["detected_at"] and record["timestamp"] == record["detected_at"]
    assert composite.sink_errors == 1
    lines = Path(__import__("os").environ["SENTINELX_ALERT_LOG"]).read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["source_ip"] == "9.9.9.9"
    assert qone("SELECT COUNT(*) FROM alerts WHERE source_ip='9.9.9.9'")[0] == 1


def test_build_sink_from_env_adds_webhook_only_when_configured(monkeypatch):
    monkeypatch.delenv("SENTINELX_WEBHOOK_URL", raising=False)
    assert [type(s) for s in build_sink_from_env().sinks] == [JsonlSink, SqliteSink]
    monkeypatch.setenv("SENTINELX_WEBHOOK_URL", "https://hooks.example/secret-token-123")
    sink = build_sink_from_env()
    try:
        assert isinstance(sink.sinks[-1], WebhookSink)
    finally:
        sink.close()


# ------------------------------------------------------------------ webhook


SECRET_URL = "https://hooks.example.com/services/T000/B000/SUPER-SECRET-TOKEN"


def make_webhook(post, **kw):
    sleeps: list[float] = []
    kw.setdefault("cooldown", 60.0)
    wh = WebhookSink(SECRET_URL, post=post, sleep=lambda s: sleeps.append(s) or False, backoff=0.5, **kw)
    wh.sleeps = sleeps  # type: ignore[attr-defined]
    return wh


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end and not cond():
        time.sleep(0.01)
    return cond()


def test_webhook_payload_modes():
    rec = alert()
    assert webhook_payload(rec, "generic")["source_ip"] == "10.0.0.5"
    assert "PORT_SCAN" in webhook_payload(rec, "slack")["text"]
    assert len(webhook_payload(alert(message="x" * 5000), "discord")["content"]) <= 2000
    with pytest.raises(ValueError):
        webhook_payload(rec, "teams")
    with pytest.raises(ValueError):
        WebhookSink("ftp://x/y")
    with pytest.raises(ValueError):
        WebhookSink("https://x/y", mode="teams")


def test_webhook_delivers_json_and_dedups_per_type_and_source_in_event_time():
    posted = []
    wh = make_webhook(lambda url, body, timeout: posted.append((url, json.loads(body))))
    try:
        wh.emit(alert(last_seen=1000.0))
        wh.emit(alert(last_seen=1030.0))  # same (type, source) inside the 60 s cooldown -> suppressed
        wh.emit(alert(last_seen=1100.0))  # past the cooldown
        wh.emit(alert(last_seen=1001.0, source_ip="10.0.0.6"))  # different source
        wh.emit(alert(last_seen=1002.0, threat_type="SYN_FLOOD"))  # different type
        assert wait_for(lambda: wh.sent == 4)
        assert wh.suppressed == 1 and wh.failures == 0
        assert all(u == SECRET_URL for u, _ in posted) and posted[0][1]["threat_type"] == "PORT_SCAN"
    finally:
        wh.close()


def test_webhook_retries_three_times_with_exponential_backoff_then_counts_failure(caplog):
    attempts = []

    def failing(url, body, timeout):
        attempts.append(1)
        raise OSError("connection refused")

    wh = make_webhook(failing)
    try:
        with caplog.at_level(logging.DEBUG):
            wh.emit(alert())
            assert wait_for(lambda: wh.failures == 1)
        assert len(attempts) == 4  # first try + 3 retries
        assert wh.sleeps == [0.5, 1.0, 2.0]
        assert wh.sent == 0
    finally:
        wh.close()


def test_webhook_succeeds_after_transient_failures():
    calls = []

    def flaky(url, body, timeout):
        calls.append(1)
        if len(calls) < 3:
            raise OSError("transient")

    wh = make_webhook(flaky)
    try:
        wh.emit(alert())
        assert wait_for(lambda: wh.sent == 1)
        assert len(calls) == 3 and wh.failures == 0
    finally:
        wh.close()


def test_webhook_never_blocks_the_engine_and_counts_overflow():
    gate = threading.Event()
    wh = make_webhook(lambda url, body, timeout: gate.wait(10), queue_max=2)
    try:
        start = time.perf_counter()
        for i in range(50):
            wh.emit(alert(source_ip=f"10.9.0.{i}", last_seen=float(i)))
        assert time.perf_counter() - start < 1.0  # post is blocked, emit still returns immediately
        assert wh.failures >= 40  # queue_max=2 (+1 in flight): the rest are dropped and counted
    finally:
        gate.set()
        wh.close()


def test_webhook_url_never_appears_in_logs_repr_metrics_or_api(caplog, monkeypatch):
    def failing(url, body, timeout):
        raise urllib.error.URLError(f"cannot reach {url}")

    import urllib.error

    wh = make_webhook(failing)
    sensor = Sensor(sink=CompositeSink([wh]), utcnow=lambda: NOW)
    try:
        with caplog.at_level(logging.DEBUG):
            wh.emit(alert())
            assert wait_for(lambda: wh.failures == 1)
            sensor.write_status()
        everything = caplog.text + repr(wh) + json.dumps(sensor.collect_status())
        everything += authed_client(api_mod.app).get("/api/v1/sensor/status").get_data(as_text=True)
        assert "SUPER-SECRET-TOKEN" not in everything and "hooks.example.com" not in everything
        assert sensor.collect_status()["webhook_failures"] == 1
    finally:
        wh.close()


def test_processor_with_slow_webhook_still_returns_quickly_and_keeps_rule_alerts():
    gate = threading.Event()
    wh = make_webhook(lambda url, body, timeout: gate.wait(10))
    sensor = Sensor(sink=CompositeSink([SqliteSink(), wh]))
    try:
        start = time.perf_counter()
        alerts = []
        for pkt in generate_scenario("fast_vertical_scan")[0]:
            alerts.extend(sensor.processor.process(pkt))
        assert time.perf_counter() - start < 5.0
        assert alerts and qone("SELECT COUNT(*) FROM alerts")[0] == len(alerts)
    finally:
        gate.set()
        wh.close()
