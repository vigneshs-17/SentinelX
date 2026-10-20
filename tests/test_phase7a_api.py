"""Step 7a backend: filters, sorting, totals, triage join, overview aggregates, assignees, destination_port."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

import backend.api as api_mod
from backend import accounts
from backend.api import app
from database.database import get_connection, insert_alert
from database.migrations import apply_migrations
from tests.support import authed_client

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def alert(minutes_ago, **kw):
    when = NOW - timedelta(minutes=minutes_ago)
    base = {
        "timestamp": iso(when),
        "detected_at": iso(when),
        "threat_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "severity": "HIGH",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.9.9.9",
        "destination_port": 22,
        "protocol": "TCP",
        "message": "scan from somewhere",
        "sensor_id": "s",
    }
    base.update(kw)
    insert_alert(base)


@pytest.fixture(autouse=True)
def pinned_clock(monkeypatch):
    monkeypatch.setattr(api_mod, "utcnow", lambda: NOW)


@pytest.fixture
def seeded():
    alert(5, severity="HIGH", source_ip="10.0.0.5", destination_port=22, message="alpha 100% match")
    alert(
        10,
        severity="LOW",
        source_ip="10.0.0.6",
        destination_port=80,
        threat_type="SYN_FLOOD",
        scan_type=None,
        message="beta_literal",
    )
    alert(
        15,
        severity="MEDIUM",
        source_ip="192.168.1.9",
        destination_port=22,
        threat_type="VOLUMETRIC",
        scan_type=None,
        message="gamma",
    )
    alert(20, severity="HIGH", source_ip="10.0.0.5", destination_port=443, message="delta")
    alert(3000, severity="LOW", source_ip="172.16.0.1", destination_port=None, message="old one")  # ~2 days ago
    return authed_client(app, "viewer")


def ids(resp):
    return [a["id"] for a in resp.get_json()]


def test_alert_fields_include_destination_port_triage_status_and_total(seeded):
    resp = seeded.get("/api/v1/alerts?limit=2")
    assert resp.status_code == 200 and resp.headers["X-Total-Count"] == "5" and len(resp.get_json()) == 2
    first = resp.get_json()[0]
    assert first["destination_port"] == 22 and first["triage_status"] == "new" and first["assignee"] is None


def test_filters_since_until_dport_q_min_id_and_status(seeded):
    q = lambda s: seeded.get(f"/api/v1/alerts?{s}")  # noqa: E731
    assert len(q("until=" + iso(NOW - timedelta(minutes=12)).replace("+", "%2B")).get_json()) == 3
    assert len(q("since=" + iso(NOW - timedelta(minutes=12)).replace("+", "%2B")).get_json()) == 2
    assert len(q("dport=22").get_json()) == 2 and q("dport=70000").status_code == 400
    assert len(q("q=ALPHA").get_json()) == 1  # case-insensitive substring
    assert (
        len(q("q=100%25").get_json()) == 1 and q("q=a%25h").get_json() == []
    )  # % is literal, not a wildcard (would match "alpha")
    assert len(q("q=beta_lit").get_json()) == 1 and q("q=b_ta").get_json() == []  # _ is literal too
    all_ids = sorted(ids(q("limit=500")))
    assert ids(q(f"min_id={all_ids[2]}&sort=id&order=asc")) == all_ids[3:]
    assert len(q("status=new").get_json()) == 5 and q("status=resolved_tp").get_json() == []
    assert q("status=bogus").status_code == 400 and q("min_id=-1").status_code == 400


def test_sorting_orders_and_rejects_unknown_columns(seeded):
    rows = lambda s: seeded.get(f"/api/v1/alerts?{s}").get_json()  # noqa: E731
    assert [r["severity"] for r in rows("sort=severity&order=desc&limit=3")] == ["HIGH", "HIGH", "MEDIUM"]
    assert [r["source_ip"] for r in rows("sort=source_ip&order=asc&limit=2")] == ["10.0.0.5", "10.0.0.5"]
    newest = rows("sort=detected_at&order=desc")
    assert [r["detected_at"] for r in newest] == sorted((r["detected_at"] for r in newest), reverse=True)
    assert [r["detected_at"] for r in rows("sort=detected_at&order=asc")] == sorted(r["detected_at"] for r in newest)
    assert seeded.get("/api/v1/alerts?sort=message").status_code == 400
    assert seeded.get("/api/v1/alerts?sort=id;DROP").status_code == 400
    assert seeded.get("/api/v1/alerts?order=sideways").status_code == 400


def test_triage_status_joins_into_list_filter_and_sort(seeded):
    analyst = authed_client(app, "analyst")
    target = ids(seeded.get("/api/v1/alerts?sort=id&order=asc"))[0]
    assert analyst.post(f"/api/v1/alerts/{target}/triage", json={"status": "resolved_fp"}).status_code == 200
    one = seeded.get("/api/v1/alerts?status=resolved_fp").get_json()
    assert [a["id"] for a in one] == [target] and one[0]["triage_status"] == "resolved_fp"
    assert target not in ids(seeded.get("/api/v1/alerts?status=new&limit=500"))
    assert seeded.get("/api/v1/alerts?status=new").headers["X-Total-Count"] == "4"
    assert ids(seeded.get("/api/v1/alerts?sort=status&order=desc&limit=1")) == [target]


def test_overview_counts_buckets_and_tops(seeded):
    body = seeded.get("/api/v1/overview").get_json()
    assert body["total"] == 4 and body["severity"] == {
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
    }  # the 2-day-old one is outside 24 h
    assert body["open"] == 4 and body["resolved"] == 0 and body["triage"]["new"] == 4
    assert body["top_sources"][0] == {"value": "10.0.0.5", "count": 2}
    assert body["top_ports"][0] == {"value": 22, "count": 2}
    assert body["bucket_minutes"] == 5 and sum(p["count"] for p in body["timeline"]) == 4  # 1441 min / 300 buckets
    assert body["timeline"] == sorted(body["timeline"], key=lambda p: p["t"])

    week = seeded.get("/api/v1/overview?since=" + iso(NOW - timedelta(days=7)).replace("+", "%2B")).get_json()
    assert week["total"] == 5 and week["bucket_minutes"] > body["bucket_minutes"]
    hour = seeded.get("/api/v1/overview?since=" + iso(NOW - timedelta(hours=1)).replace("+", "%2B")).get_json()
    assert hour["bucket_minutes"] == 1 and hour["total"] == 4
    narrow = seeded.get(
        "/api/v1/overview?since="
        + iso(NOW - timedelta(minutes=12)).replace("+", "%2B")
        + "&until="
        + iso(NOW - timedelta(minutes=4)).replace("+", "%2B")
    ).get_json()
    assert narrow["total"] == 2 and narrow["severity"]["LOW"] == 1


def test_overview_reflects_triage_and_respects_filters(seeded):
    analyst = authed_client(app, "analyst")
    first = ids(seeded.get("/api/v1/alerts?sort=id&order=asc"))[:2]
    analyst.post(f"/api/v1/alerts/{first[0]}/triage", json={"status": "investigating"})
    analyst.post(f"/api/v1/alerts/{first[1]}/triage", json={"status": "resolved_tp"})
    body = seeded.get("/api/v1/overview").get_json()
    assert body["triage"]["investigating"] == 1 and body["resolved"] == 1 and body["open"] == 3
    only_high = seeded.get("/api/v1/overview?severity=HIGH").get_json()
    assert only_high["total"] == 2 and only_high["top_sources"] == [{"value": "10.0.0.5", "count": 2}]


def test_overview_validation(seeded):
    for bad in ("since=nope", "since=2026-01-01T00:00:00", "severity=X", "bogus=1", "dport=abc"):
        assert seeded.get(f"/api/v1/overview?{bad}").status_code == 400, bad


def test_empty_overview_is_well_formed():
    body = authed_client(app, "viewer").get("/api/v1/overview").get_json()
    assert body["total"] == 0 and body["timeline"] == [] and body["top_sources"] == [] and body["top_ports"] == []


def test_assignees_endpoint_lists_enabled_usernames_for_analysts_only():
    accounts.create_user("ann-analyst", "a long enough password", "analyst")
    accounts.create_user("vic-viewer", "a long enough password", "viewer")
    accounts.create_user("dan-disabled", "a long enough password", "viewer")
    accounts.set_disabled("dan-disabled", True)
    assert authed_client(app, "analyst").get("/api/v1/assignees").get_json() == ["ann-analyst", "vic-viewer"]
    assert authed_client(app, "viewer").get("/api/v1/assignees").status_code == 403
    assert app.test_client().get("/api/v1/assignees").status_code == 401
    assert "password_hash" not in authed_client(app, "analyst").get("/api/v1/assignees").get_data(as_text=True)


def test_migration_5_adds_destination_port_to_an_existing_v4_database():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, threat_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT, destination_ip TEXT, protocol TEXT, message TEXT)"
    )
    conn.execute("PRAGMA user_version = 1")
    assert apply_migrations(conn) == 6
    assert "destination_port" in {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert apply_migrations(conn) == 6  # idempotent
    conn.close()


def test_destination_port_is_persisted_by_insert_alert():
    alert(1, destination_port=8443)
    conn = get_connection()
    try:
        assert conn.execute("SELECT destination_port FROM alerts").fetchone()[0] == 8443
    finally:
        conn.close()
