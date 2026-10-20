"""Static checks of the container/CI configuration plus the stdlib helper scripts used by CI."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from database.database import insert_sensor_status
from scripts import healthcheck, zap_gate

ROOT = Path(__file__).resolve().parent.parent


def load(rel):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def test_compose_sensor_is_least_privilege_and_api_is_locked_down():
    svc = load("docker-compose.yml")["services"]
    s, a = svc["sensor"], svc["api"]
    assert not s.get("privileged") and not a.get("privileged")
    assert s["network_mode"] == "host" and s["cap_add"] == ["NET_RAW"] and s["cap_drop"] == ["ALL"]
    assert a["read_only"] is True and a["cap_drop"] == ["ALL"] and "cap_add" not in a
    assert a["ports"] == ["127.0.0.1:5000:5000"]
    assert "alerts:/data/alerts:ro" in a["volumes"] and "alerts:/data/alerts" in s["volumes"]
    assert any(v.startswith("appdata:") and not v.endswith(":ro") for v in a["volumes"])
    assert a["depends_on"]["sensor"]["condition"] == "service_healthy"
    assert "no-new-privileges:true" in a["security_opt"] and a["user"].split(":")[0] != "0"


def test_dockerfile_non_root_two_targets_healthchecks_and_caps_only_on_sensor():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    api, sensor = text.split("AS api")[1].split("AS sensor")[0], text.split("AS sensor")[1]
    assert "FROM python:3.12-slim AS base" in text
    assert "USER sentinelx" in api and "USER sentinelx" in sensor
    assert "HEALTHCHECK" in api and "HEALTHCHECK" in sensor
    assert "setcap" in sensor and "setcap" not in api  # file caps would break exec under cap_drop: ALL
    assert "--uid 10001" in text and "USER root" not in text


def test_dockerignore_keeps_secrets_data_and_tests_out_of_the_image():
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    for must in (".git", ".venv", "tests", "*.db", ".env", "*.pcap", "models", "*.key"):
        assert must in lines


def test_ci_workflow_has_all_required_jobs_and_gates_on_them():
    wf = load(".github/workflows/ci.yml")
    jobs = wf["jobs"]
    for job in ("api-fuzz", "secret-scan", "container-scan", "compose-integration"):
        assert job in jobs and job in jobs["quality-gate"]["needs"]
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for needle in (
        "zaproxy/action-baseline@",
        "aquasecurity/trivy-action@",
        "gitleaks/gitleaks-action@",
        "schemathesis run docs/openapi.yaml",
        "ignore-unfixed: true",
        "scripts/zap_gate.py",
    ):
        assert needle in text, needle


# ------------------------------------------------------------------ zap gate


def report(*alerts):
    return {
        "site": [
            {
                "alerts": [
                    {"pluginid": pid, "name": f"rule {pid}", "riskcode": str(risk), "riskdesc": "x"}
                    for pid, risk in alerts
                ]
            }
        ]
    }


def test_zap_gate_blocks_medium_and_high_only_unless_justified(tmp_path):
    rules = tmp_path / "rules.tsv"
    rules.write_text("# comment\n10055\tIGNORE\tstatic file, accepted\n", encoding="utf-8")
    ignored = zap_gate.load_rules(rules)
    assert zap_gate.blocking_alerts(report(("1", 0), ("2", 1)), ignored) == []
    assert [b[0] for b in zap_gate.blocking_alerts(report(("3", 2), ("4", 3), ("10055", 2)), ignored)] == ["3", "4"]

    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(report(("3", 2))), encoding="utf-8")
    assert zap_gate.main([str(rep), str(rules)]) == 1
    rep.write_text(json.dumps(report(("10055", 3), ("9", 1))), encoding="utf-8")
    assert zap_gate.main([str(rep), str(rules)]) == 0
    assert zap_gate.main([]) == 2 and zap_gate.main([str(tmp_path / "missing.json"), str(rules)]) == 2


@pytest.mark.parametrize("line", ["10055\tIGNORE\t", "10055\tIGNORE", "10055\tWARN\tbecause", "garbage"])
def test_zap_rules_need_a_justification(tmp_path, line):
    rules = tmp_path / "rules.tsv"
    rules.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        zap_gate.load_rules(rules)


def test_committed_zap_rules_file_is_valid():
    path = ROOT / ".zap" / "rules.tsv"
    assert path.read_text(encoding="utf-8").lstrip().startswith("#")  # the file explains its own contract
    rules = zap_gate.load_rules(path)
    # No blanket ignores: few entries, numeric plugin ids, and a real sentence of justification for each.
    assert len(rules) <= 5
    assert all(pid.isdigit() and len(why) >= 20 for pid, why in rules.items())


# ------------------------------------------------------------------ healthcheck


def beat(ts):
    return {
        "sensor_id": "s",
        "last_seen": ts.isoformat(timespec="seconds"),
        "received": 1,
        "dropped": 0,
        "queue_depth": 0,
        "pps_10s": 0.0,
        "state_size": 0,
        "evictions": 0,
        "webhook_failures": 0,
    }


def test_sensor_healthcheck_follows_heartbeat_age(monkeypatch, tmp_path):
    assert healthcheck.check_sensor() is False
    insert_sensor_status(beat(datetime.now(UTC) - timedelta(seconds=120)))
    assert healthcheck.check_sensor() is False
    insert_sensor_status(beat(datetime.now(UTC)))
    assert healthcheck.check_sensor() is True
    monkeypatch.setenv("SENTINELX_DB_PATH", str(tmp_path / "nope.db"))
    assert healthcheck.check_sensor() is False
    assert healthcheck.main(["bogus"]) == 2 and healthcheck.main([]) == 2


def test_api_healthcheck_hits_health_endpoint(monkeypatch):
    import threading

    import waitress

    from backend.api import app

    server = waitress.create_server(app, host="127.0.0.1", port=0, threads=2)
    monkeypatch.setenv("SENTINELX_API_PORT", str(server.effective_port))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        assert healthcheck.check_api() is True
    finally:
        server.close()
        t.join(timeout=5)
    assert healthcheck.check_api() is False  # nothing listening any more


def test_sqlite_is_importable_marker():
    assert sqlite3.sqlite_version_info >= (3, 22)  # read-only WAL access needs SQLite >= 3.22


def test_e2e_job_exists_and_browser_tests_are_collected_only_under_the_marker():
    import subprocess
    import sys

    wf = load(".github/workflows/ci.yml")
    assert "e2e" in wf["jobs"] and "e2e" in wf["jobs"]["quality-gate"]["needs"]
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "playwright install --with-deps chromium" in text and "pytest -m e2e tests/e2e" in text

    def collected(*args):
        out = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )  # noqa: S603
        return out.stdout

    assert "tests/e2e" not in collected("tests/e2e")  # the default run never starts a browser
    marked = collected("-m", "e2e", "tests/e2e")
    assert (
        marked.count("tests/e2e/test_console_flows.py::") >= 15
        and marked.count("tests/e2e/test_accessibility.py::") >= 20
    )
