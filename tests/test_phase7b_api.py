"""Step 7b backend: destination_ip filter, graph, sensor history, export (CSV injection, caps, audit), JS layout."""

import csv
import io
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import backend.api as api_mod
from backend import accounts
from backend.api import app, csv_safe
from database.database import insert_alert, insert_sensor_status
from tests.support import authed_client

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent.parent


def iso(dt):
    return dt.isoformat(timespec="seconds")


def alert(minutes_ago=5, **kw):
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
        "message": "plain message",
        "sensor_id": "s",
    }
    base.update(kw)
    insert_alert(base)


@pytest.fixture(autouse=True)
def pinned_clock(monkeypatch):
    monkeypatch.setattr(api_mod, "utcnow", lambda: NOW)


@pytest.fixture
def viewer():
    return authed_client(app, "viewer")


# ------------------------------------------------------------------ destination_ip filter


def test_destination_ip_filter_exact_cidr_and_validation(viewer):
    alert(destination_ip="10.9.9.9")
    alert(destination_ip="192.168.1.20")
    q = lambda s: viewer.get(f"/api/v1/alerts?{s}")  # noqa: E731
    assert len(q("destination_ip=192.168.1.20").get_json()) == 1
    assert len(q("destination_ip=192.168.0.0/16").get_json()) == 1
    assert len(q("destination_ip=10.0.0.0/8").get_json()) == 1
    assert q("destination_ip=nope").status_code == 400 and q("destination_ip=1.2.3.4/40").status_code == 400
    assert viewer.get("/api/v1/overview?destination_ip=10.9.9.9").get_json()["total"] == 1


# ------------------------------------------------------------------ graph


def test_graph_edges_nodes_roles_and_default_window(viewer):
    for _ in range(3):
        alert(source_ip="1.1.1.1", destination_ip="2.2.2.2", threat_type="PORT_SCAN")
    alert(source_ip="1.1.1.1", destination_ip="2.2.2.2", threat_type="SYN_FLOOD", scan_type=None)
    alert(source_ip="2.2.2.2", destination_ip="3.3.3.3", threat_type="VOLUMETRIC", scan_type=None)
    alert(minutes_ago=3000, source_ip="9.9.9.9", destination_ip="8.8.8.8")  # outside the default 24 h window
    body = viewer.get("/api/v1/graph").get_json()
    edges = {(e["source"], e["target"], e["threat_type"]): e["count"] for e in body["edges"]}
    assert edges == {
        ("1.1.1.1", "2.2.2.2", "PORT_SCAN"): 3,
        ("1.1.1.1", "2.2.2.2", "SYN_FLOOD"): 1,
        ("2.2.2.2", "3.3.3.3", "VOLUMETRIC"): 1,
    }
    roles = {n["id"]: (n["role"], n["count"]) for n in body["nodes"]}
    assert roles == {"1.1.1.1": ("source", 4), "2.2.2.2": ("both", 5), "3.3.3.3": ("target", 1)}
    assert body["truncated"] is False and body["total_nodes"] == 3
    assert [n["id"] for n in body["nodes"]][0] == "2.2.2.2"  # busiest node first
    assert viewer.get("/api/v1/graph?threat_type=VOLUMETRIC").get_json()["edges"][0]["target"] == "3.3.3.3"
    week = viewer.get("/api/v1/graph?since=" + iso(NOW - timedelta(days=7)).replace("+", "%2B")).get_json()
    assert week["total_nodes"] == 5


def test_graph_is_capped_and_reports_truncation(viewer, monkeypatch):
    monkeypatch.setattr(api_mod, "GRAPH_MAX_NODES", 4)
    monkeypatch.setattr(api_mod, "GRAPH_MAX_EDGES", 100)
    for i in range(10):
        alert(source_ip="7.7.7.7", destination_ip=f"10.1.0.{i}")
    body = viewer.get("/api/v1/graph").get_json()
    assert len(body["nodes"]) <= 4 and body["truncated"] is True and body["total_nodes"] == 11
    assert all(
        e["source"] in {n["id"] for n in body["nodes"]} and e["target"] in {n["id"] for n in body["nodes"]}
        for e in body["edges"]
    )
    monkeypatch.setattr(api_mod, "GRAPH_MAX_NODES", 200)
    monkeypatch.setattr(api_mod, "GRAPH_MAX_EDGES", 3)
    assert viewer.get("/api/v1/graph").get_json()["truncated"] is True


def test_graph_validation_and_empty(viewer):
    assert viewer.get("/api/v1/graph").get_json()["nodes"] == []
    for bad in ("severity=X", "bogus=1", "source_ip=nope"):
        assert viewer.get(f"/api/v1/graph?{bad}").status_code == 400


# ------------------------------------------------------------------ sensor history


def beat(minutes_ago, received, dropped, pps=10.0, queue=0, state=5):
    insert_sensor_status(
        {
            "sensor_id": "s1",
            "last_seen": iso(NOW - timedelta(minutes=minutes_ago)),
            "received": received,
            "dropped": dropped,
            "queue_depth": queue,
            "pps_10s": pps,
            "state_size": state,
            "evictions": 0,
            "webhook_failures": 0,
        }
    )


def test_metrics_history_window_points_drop_rate_and_threshold(viewer, monkeypatch):
    monkeypatch.setattr(api_mod, "DROP_WARN_RATIO", 0.02)
    beat(45, 0, 0)  # outside the 30 minute window
    beat(25, 1000, 0)
    beat(10, 2000, 30, pps=55.5, queue=7, state=99)
    beat(1, 3000, 60)
    body = viewer.get("/api/v1/metrics/history").get_json()
    assert body["window_minutes"] == 30 and len(body["points"]) == 3
    assert body["points"][1]["pps_10s"] == 55.5 and body["points"][1]["queue_depth"] == 7
    assert body["drop_rate"] == pytest.approx(60 / 2000) and body["drop_warn_ratio"] == 0.02
    assert [p["last_seen"] for p in body["points"]] == sorted(p["last_seen"] for p in body["points"])
    assert len(viewer.get("/api/v1/metrics/history?minutes=60").get_json()["points"]) == 4


def test_metrics_history_empty_and_validation(viewer):
    body = viewer.get("/api/v1/metrics/history").get_json()
    assert body["points"] == [] and body["drop_rate"] is None
    for bad in ("minutes=0", "minutes=181", "minutes=x", "other=1"):
        assert viewer.get(f"/api/v1/metrics/history?{bad}").status_code == 400


# ------------------------------------------------------------------ export


def parse_csv(resp):
    return list(csv.reader(io.StringIO(resp.get_data(as_text=True))))


def test_csv_export_columns_filters_headers_and_audit(viewer):
    alert(1, severity="HIGH", message="first")
    alert(2, severity="LOW", message="second")
    resp = viewer.get("/api/v1/alerts/export?format=csv&severity=HIGH")
    rows = parse_csv(resp)
    assert resp.status_code == 200 and resp.mimetype == "text/csv"
    assert rows[0] == [
        "id",
        "detected_at",
        "severity",
        "threat_type",
        "scan_type",
        "source_ip",
        "destination_ip",
        "destination_port",
        "protocol",
        "confidence",
        "triage_status",
        "assignee",
        "message",
    ]
    assert len(rows) == 2 and rows[1][2] == "HIGH" and rows[1][-1] == "first"
    assert resp.headers["Content-Disposition"].startswith(
        'attachment; filename="sentinelx-alerts-20261020T120000Z.csv"'
    )
    assert resp.headers["X-Total-Count"] == "1" and resp.headers["X-Export-Truncated"] == "false"
    audit = accounts.query_audit(action="alerts.export")
    assert (
        len(audit) == 1
        and audit[0]["detail"] == {"format": "csv", "rows": 1, "truncated": False}
        and audit[0]["actor"].startswith("apikey:")
    )


def test_csv_formula_injection_is_neutralised(viewer):
    payloads = ['=HYPERLINK("http://evil","x")', "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"]
    for i, payload in enumerate(payloads):
        alert(i + 1, message=payload, source_ip=f"10.2.0.{i}")
    alert(9, message="safe text - with dash", source_ip="10.2.0.99")
    rows = parse_csv(viewer.get("/api/v1/alerts/export?format=csv&sort=id&order=asc"))
    messages = [r[-1] for r in rows[1:]]
    assert messages[:6] == ["'" + p for p in payloads] and messages[6] == "safe text - with dash"
    assert not any(m[:1] in "=+-@\t\r" for m in messages)
    assert csv_safe("=1") == "'=1" and csv_safe(5) == 5 and csv_safe(None) is None and csv_safe("ok") == "ok"
    # IP-like and enum columns are covered by the same guard
    alert(10, threat_type="PORT_SCAN", source_ip="10.2.0.100", message="x")
    assert all(c[:1] not in "=+@" for r in parse_csv(viewer.get("/api/v1/alerts/export")) for c in r if c)


def test_json_export_and_validation(viewer):
    alert(1, message="one")
    resp = viewer.get("/api/v1/alerts/export?format=json")
    data = json.loads(resp.get_data(as_text=True))
    assert resp.mimetype == "application/json" and data[0]["message"] == "one" and data[0]["triage_status"] == "new"
    assert resp.headers["Content-Disposition"].endswith('.json"')
    for bad in ("format=xml", "limit=0", "sort=message", "order=up", "bogus=1", "severity=X"):
        assert viewer.get(f"/api/v1/alerts/export?{bad}").status_code == 400, bad
    assert app.test_client().get("/api/v1/alerts/export").status_code == 401


def test_export_row_cap_and_truncation_flag(viewer, monkeypatch):
    monkeypatch.setattr(api_mod, "EXPORT_MAX_ROWS", 3)
    for i in range(5):
        alert(i + 1, source_ip=f"10.3.0.{i}")
    resp = viewer.get("/api/v1/alerts/export?format=csv")
    assert (
        len(parse_csv(resp)) == 4
        and resp.headers["X-Export-Truncated"] == "true"
        and resp.headers["X-Total-Count"] == "5"
    )
    assert viewer.get("/api/v1/alerts/export?limit=4").status_code == 400  # above the server cap
    assert len(parse_csv(viewer.get("/api/v1/alerts/export?limit=2"))) == 3
    assert accounts.query_audit(action="alerts.export")[0]["detail"]["truncated"] is True


def test_export_uses_the_same_filters_and_sort_as_the_list(viewer):
    alert(1, severity="HIGH", source_ip="10.4.0.1")
    alert(2, severity="LOW", source_ip="10.4.0.2")
    alert(3, severity="HIGH", source_ip="10.4.0.3")
    listed = [a["id"] for a in viewer.get("/api/v1/alerts?severity=HIGH&sort=source_ip&order=asc").get_json()]
    exported = [
        int(r[0]) for r in parse_csv(viewer.get("/api/v1/alerts/export?severity=HIGH&sort=source_ip&order=asc"))[1:]
    ]
    assert listed == exported and len(listed) == 2


# ------------------------------------------------------------------ JS layout (needs node)


def test_force_layout_properties_via_node():
    node = shutil.which("node")
    if node is None:
        if os.getenv("CI"):
            pytest.fail("node is required in CI for the layout test")
        pytest.skip("node not installed locally")
    out = subprocess.run(
        [node, str(ROOT / "tests" / "js" / "layout_check.mjs")], capture_output=True, text=True, timeout=60, check=True
    )  # noqa: S603
    result = json.loads(out.stdout.strip().splitlines()[-1])
    ms = result.pop("ms200")
    assert all(result.values()), result
    assert ms < 5000
