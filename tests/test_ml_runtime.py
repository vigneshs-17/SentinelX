"""ML runtime role: off by default, fail closed, additive only. ML never suppresses a rule alert."""

import json
import logging

import numpy as np
import pytest

import ml.artifact as artifact
import ml.runtime as runtime
from capture.processor import PacketProcessor
from eval.scenarios import generate_scenario
from ml.artifact import write_gate
from ml.build import build_scenario_flows
from ml.model import train_from_flows
from ml.runtime import MLScorer, ml_enabled

KEY = "runtime-test-key-0123456789"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv(artifact.KEY_ENV, KEY)
    monkeypatch.delenv("SENTINELX_ML", raising=False)


class Stub:
    classes_ = np.array(["BENIGN", "X"])

    def __init__(self, p_attack=0.0, fail=False):
        self.p, self.fail = p_attack, fail

    def predict_proba(self, x):
        if self.fail:
            raise RuntimeError("model exploded")
        return np.tile([1.0 - self.p, self.p], (len(x), 1))


def scorer(p=0.0, fail=False, cooldown=30.0):
    bundle = {
        "model": Stub(p, fail),
        "classes": ["BENIGN", "X"],
        "benign_label": "BENIGN",
        "threshold": 0.5,
        "medium_threshold": 0.75,
    }
    return MLScorer(bundle, cooldown=cooldown)


def run(processor, packets):
    out = []
    for p in packets:
        out.extend(processor.process(p))
    return out


def rule_view(alerts):
    return [
        (a["threat_type"], a["severity"], a["source_ip"], a["destination_ip"], a["first_seen"], a["last_seen"])
        for a in alerts
        if a["threat_type"] != "ML_ANOMALY"
    ]


def scan_packets():
    return generate_scenario("fast_vertical_scan")[0] + generate_scenario("syn_flood_spoofed")[0]


@pytest.mark.parametrize("kind", ["benign", "suspicious", "certain", "model_error"])
def test_ml_never_suppresses_or_alters_a_rule_alert(kind):
    packets = scan_packets()
    base_sink: list = []
    base = PacketProcessor(alert_sink=base_sink.append, ml_scorer=None)
    assert base.ml is None
    expected = run(base, packets)
    assert rule_view(expected), "scenario must raise rule alerts"

    sc = {
        "benign": scorer(0.0),
        "suspicious": scorer(0.6),
        "certain": scorer(0.99),
        "model_error": scorer(0.9, fail=True),
    }[kind]
    sink: list = []
    proc = PacketProcessor(alert_sink=sink.append, ml_scorer=sc)
    got = run(proc, packets)
    if kind != "model_error":  # a failing model raises only if called directly; the processor swallows it
        got += sc.flush()  # flows still open at end of capture

    assert rule_view(got) == rule_view(expected)  # every rule alert present, same severity/time/endpoints
    persisted_rules = [a for a in sink if a["threat_type"] != "ML_ANOMALY"]
    assert len(persisted_rules) == len(rule_view(expected))
    ml_alerts = [a for a in got if a["threat_type"] == "ML_ANOMALY"]
    if kind in ("benign", "model_error"):
        assert not ml_alerts
    else:
        assert ml_alerts and all(a["severity"] in ("LOW", "MEDIUM") for a in ml_alerts)


def test_ml_alert_severity_cooldown_and_links_to_rule_alerts():
    low, high = scorer(0.6), scorer(0.99)
    pkt = lambda ts, sport: {  # noqa: E731
        "ts": ts,
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "source_port": sport,
        "destination_port": 80,
        "protocol": "TCP",
        "packet_size": 60,
        "tcp_flags": 0x02,
    }
    for sc, sev in ((low, "LOW"), (high, "MEDIUM")):
        sc.note_rule_alert(
            {"threat_type": "PORT_SCAN", "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "last_seen": 100.5}
        )
        alerts = []
        for ts, sport in ((100.0, 5000), (101.0, 5001), (200.0, 5002)):  # first two within the 30 s cooldown window
            alerts += sc.observe(pkt(ts, sport))
        alerts += sc.flush()
        assert [a["severity"] for a in alerts] == [sev, sev]  # 100/101 collapse to one; 200 is a new alert
        assert alerts[0]["threat_type"] == "ML_ANOMALY" and alerts[0]["ml_score"] == pytest.approx(
            0.6 if sev == "LOW" else 0.99
        )
        assert alerts[0]["evidence"]["related_rule_alerts"][0]["threat_type"] == "PORT_SCAN"


def test_annotation_is_additive_only():
    sc = scorer(0.9)
    rule = {"threat_type": "PORT_SCAN", "severity": "HIGH", "source_ip": "1.1.1.1"}
    sc.annotate(rule, {"ml_score": 0.9, "ml_label": "X"})
    assert rule == {
        "threat_type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "1.1.1.1",
        "ml_score": 0.9,
        "ml_label": "X",
    }


def test_persistence_failure_does_not_break_the_pipeline():
    def bad_sink(_alert):
        raise OSError("disk full")

    proc = PacketProcessor(alert_sink=bad_sink, ml_scorer=scorer(0.9))
    assert rule_view(run(proc, scan_packets()))


# ------------------------------------------------------------------ enablement / fail closed


def test_ml_is_off_by_default_and_flag_parsing(monkeypatch):
    assert ml_enabled() is False and MLScorer.from_env() is None
    for v, expect in (("on", True), ("ON", True), (" on ", True), ("off", False), ("1", False), ("true", False)):
        monkeypatch.setenv("SENTINELX_ML", v)
        assert ml_enabled() is expect


@pytest.fixture
def smoke_dir(tmp_path):
    flows = tmp_path / "f.csv.gz"
    build_scenario_flows(["benign_web_browsing", "fast_vertical_scan", "syn_flood_spoofed"], flows)
    out = tmp_path / "model"
    train_from_flows(flows, out, smoke=True)
    return out


def test_enabled_but_unverifiable_model_fails_closed(monkeypatch, tmp_path, smoke_dir, caplog):
    monkeypatch.setenv("SENTINELX_ML", "on")
    monkeypatch.setattr(runtime, "ML_MODEL_DIR", str(tmp_path / "nope"))
    with caplog.at_level(logging.ERROR, logger="sentinelx.ml.runtime"):
        assert MLScorer.from_env() is None
    assert "fail closed" in caplog.text

    monkeypatch.setattr(runtime, "ML_MODEL_DIR", str(smoke_dir))
    assert MLScorer.from_env() is None  # signed model but no gate.json
    write_gate(smoke_dir, {"decision": "FAIL", "reason": "no gain"})
    assert MLScorer.from_env() is None
    proc = PacketProcessor(alert_sink=lambda a: None)
    assert proc.ml is None and rule_view(run(proc, scan_packets()))  # rules run normally with ML disabled


def test_enabled_with_signed_pass_gate_loads_scorer(monkeypatch, smoke_dir):
    monkeypatch.setenv("SENTINELX_ML", "on")
    monkeypatch.setattr(runtime, "ML_MODEL_DIR", str(smoke_dir))
    write_gate(smoke_dir, {"decision": "PASS", "reason": "unit test"})
    sc = MLScorer.from_env()
    assert isinstance(sc, MLScorer) and 0.5 <= sc.threshold <= 1.0
    proc = PacketProcessor(alert_sink=lambda a: None)
    assert proc.ml is not None
    base = rule_view(run(PacketProcessor(alert_sink=lambda a: None, ml_scorer=None), scan_packets()))
    assert rule_view(run(proc, scan_packets())) == base
    json.dumps(sc.flush())  # ML alerts are JSON-serializable like rule alerts
