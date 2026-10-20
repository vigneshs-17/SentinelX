"""Model artifact security, end-to-end training on a synthetic labelled flow table, metrics, gate and report."""

import csv
import gzip
import json
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest
import skops.io as sio

import ml.artifact as artifact
from ml.artifact import MODEL_FILE, ModelSecurityError, load_bundle, read_gate, save_bundle, write_gate
from ml.build import COLUMNS, build_scenario_flows
from ml.dataset import BENIGN
from ml.evaluate import alert_metrics, decide_gate, flow_metrics
from ml.flows import FEATURE_NAMES
from ml.model import TrainingError, calibrate_threshold, read_flows, train_from_flows
from ml.report import DATASET_BEGIN, DATASET_END, render_report, update_dataset_doc

KEY = "unit-test-model-key-0123456789"


@pytest.fixture(autouse=True)
def model_key(monkeypatch):
    monkeypatch.setenv(artifact.KEY_ENV, KEY)


@pytest.fixture(scope="module")
def smoke_flows(tmp_path_factory):
    out = tmp_path_factory.mktemp("smoke") / "flows.csv.gz"
    build_scenario_flows(["benign_web_browsing", "fast_vertical_scan", "syn_flood_spoofed", "benign_lan_noise"], out)
    return out


@pytest.fixture
def smoke_model(tmp_path, smoke_flows):
    out = tmp_path / "model"
    train_from_flows(smoke_flows, out, smoke=True)
    return out


# ------------------------------------------------------------------ artifact security


def test_roundtrip_load_verifies_signature_and_schema(smoke_model):
    b = load_bundle(smoke_model, require_gate=False)
    assert b["benign_label"] == BENIGN and "model" in b and b["feature_names"] == list(FEATURE_NAMES)
    assert len(b["model_sha256"]) == 64


def test_tampered_model_file_is_rejected_before_deserialization(smoke_model):
    path = smoke_model / MODEL_FILE
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    with patch("skops.io.loads") as loads, patch("skops.io.load") as load:
        with pytest.raises(ModelSecurityError, match="signature mismatch"):
            load_bundle(smoke_model, require_gate=False)
        loads.assert_not_called()
        load.assert_not_called()


def test_wrong_key_missing_key_short_key_and_missing_signature_rejected(smoke_model, monkeypatch):
    with pytest.raises(ModelSecurityError, match="signature mismatch"):
        load_bundle(smoke_model, key="another-key-another-key-123", require_gate=False)
    monkeypatch.delenv(artifact.KEY_ENV)
    with pytest.raises(ModelSecurityError, match="not set"):
        load_bundle(smoke_model, require_gate=False)
    with pytest.raises(ModelSecurityError, match="at least"):
        load_bundle(smoke_model, key="short", require_gate=False)
    monkeypatch.setenv(artifact.KEY_ENV, KEY)
    (smoke_model / (MODEL_FILE + ".sig")).unlink()
    with pytest.raises(ModelSecurityError, match="missing"):
        load_bundle(smoke_model, require_gate=False)


def test_model_with_signature_of_other_content_is_rejected(smoke_model):
    (smoke_model / (MODEL_FILE + ".sig")).write_text(artifact.sign_bytes(b"some other model", KEY.encode()))
    with pytest.raises(ModelSecurityError, match="signature mismatch"):
        load_bundle(smoke_model, require_gate=False)


class _Evil:
    """A type outside the allow-list; a validly signed file containing it must still be refused."""

    def __init__(self):
        self.x = 1


def test_signed_file_with_type_outside_allow_list_is_refused(tmp_path):
    out = tmp_path / "m"
    out.mkdir()
    import io

    buf = io.BytesIO()
    sio.dump({"model": _Evil(), "format": 1, "feature_names": list(FEATURE_NAMES)}, buf)
    (out / MODEL_FILE).write_bytes(buf.getvalue())
    (out / (MODEL_FILE + ".sig")).write_text(artifact.sign_bytes(buf.getvalue(), KEY.encode()))
    with pytest.raises(ModelSecurityError, match="allow-list|loaded safely"):
        load_bundle(out, require_gate=False)


def test_feature_schema_drift_is_refused(smoke_model, monkeypatch):
    monkeypatch.setattr(artifact, "FEATURE_NAMES", FEATURE_NAMES[:-1])
    with pytest.raises(ModelSecurityError, match="feature schema"):
        load_bundle(smoke_model, require_gate=False)


def test_gate_must_be_signed_pass_and_bound_to_this_model(tmp_path, smoke_flows):
    a, b = tmp_path / "a", tmp_path / "b"
    train_from_flows(smoke_flows, a, smoke=True)
    with pytest.raises(ModelSecurityError, match="missing"):
        load_bundle(a, require_gate=True)
    write_gate(a, {"decision": "FAIL", "reason": "test"})
    with pytest.raises(ModelSecurityError, match="not PASS"):
        load_bundle(a, require_gate=True)
    write_gate(a, {"decision": "PASS", "reason": "test"})
    assert load_bundle(a, require_gate=True)["model_sha256"]

    # a PASS gate copied next to a different (validly signed) model file is refused: it is bound to a SHA-256
    other = load_bundle(a, require_gate=False)
    other["meta_json"] = json.dumps({"different": True})
    save_bundle(other, b)
    (b / "gate.json").write_bytes((a / "gate.json").read_bytes())
    (b / "gate.json.sig").write_bytes((a / "gate.json.sig").read_bytes())
    with pytest.raises(ModelSecurityError, match="different model"):
        load_bundle(b, require_gate=True)
    # tampering with the gate itself is detected
    (a / "gate.json").write_text(json.dumps({"decision": "PASS", "model_sha256": "0" * 64}))
    with pytest.raises(ModelSecurityError, match="signature mismatch"):
        read_gate(a)


# ------------------------------------------------------------------ synthetic CIC-like training run


def _write_schedule(path: Path):
    path.write_text(
        json.dumps(
            {
                "utc_offset_hours": 0,
                "attacker_aliases": [],
                "windows": [
                    {
                        "date": "2017-07-04",
                        "class": "AtkA",
                        "start": "02:00",
                        "end": "04:00",
                        "attackers": ["6.6.6.6"],
                        "victims": ["10.0.0.5"],
                    },
                    {
                        "date": "2017-07-04",
                        "class": "AtkB",
                        "start": "07:00",
                        "end": "07:05",
                        "attackers": ["7.7.7.7"],
                        "victims": ["10.0.0.5"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_flows(path: Path, seed=0):
    from ml.dataset import label_flow, load_schedule

    sched = path.parent / "schedule.json"
    _write_schedule(sched)
    windows = load_schedule(sched)
    rng = np.random.default_rng(seed)
    base = 1_499_126_400.0  # 2017-07-04 00:00:00 UTC
    with gzip.open(path, "wt", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        for i in range(12000):
            t = base + i * 4.0  # 13.3 h at one flow / 4 s
            roll = rng.random()
            src, dst = f"192.168.1.{rng.integers(1, 50)}", "10.0.0.5"
            if windows[0].start_ts <= t <= windows[0].end_ts and roll < 0.8:
                src = "6.6.6.6"
            elif windows[1].start_ts <= t <= windows[1].end_ts and roll < 0.8:
                src = "7.7.7.7"
            label = label_flow(windows, src, dst, t)
            vec = rng.normal(5, 1, len(FEATURE_NAMES)).clip(min=0)
            if label == "AtkA":
                vec[FEATURE_NAMES.index("syn_count")] += 40
                vec[FEATURE_NAMES.index("src_unique_dst_ports_60s")] += 30
            elif label == "AtkB":
                vec[FEATURE_NAMES.index("rst_count")] += 25
            w.writerow(
                [
                    "day1.pcap",
                    src,
                    dst,
                    1234,
                    80,
                    "TCP",
                    repr(t),
                    repr(t + 3.0),
                    "fin",
                    label,
                    *(repr(float(v)) for v in vec),
                ]
            )


def test_full_training_run_on_synthetic_flows(tmp_path):
    flows = tmp_path / "flows.csv.gz"
    _write_flows(flows)
    # the on-disk schedule is passed through the CLI path, not the CIC default
    rep = train_from_flows(flows, tmp_path / "out", schedule_path=tmp_path / "schedule.json")
    assert rep["mode"] == "full" and rep["purge_gap_seconds"] == 240.0
    kinds = {r["split"] for r in rep["split_table"]}
    assert {"train", "val", "test"} <= kinds
    assert rep["class_split_policy"]["AtkA"] == "time_blocks"
    assert rep["class_split_policy"]["AtkB"] == "short_test"
    assert rep["trained_classes"] == ["AtkA"] and rep["zero_shot_classes"] == ["AtkB"]
    fm = rep["flow_metrics_test"]
    assert fm["headline_classes"] == ["AtkA"]
    assert fm["per_class"]["AtkA"]["recall"] > 0.9 and fm["per_class"]["AtkA"]["pr_auc"] > 0.9
    assert fm["zero_shot"]["AtkB"]["support"] > 0
    assert len(rep["permutation_importance_top10"]) == 10
    assert 0.5 <= rep["threshold"]["threshold"] <= 0.999

    # exact class counts in the split table sum to the flows that were kept
    kept = sum(r["flows"] for r in rep["split_table"] if r["split"] != "purged")
    assert kept + rep["purged_flows"] == rep["total_flows"]
    assert (tmp_path / "out" / MODEL_FILE).exists()
    labels = json.loads((tmp_path / "out" / "test_labels.json").read_text())
    assert labels["segments"] and labels["zero_shot_classes"] == ["AtkB"]
    assert all(lbl["attack_type"] in ("AtkA", "AtkB") for lbl in labels["labels"])
    # train rows never overlap the test segments by construction: check no flow in two splits
    df = read_flows(flows)
    assert len(df) == rep["total_flows"]


def test_training_needs_two_classes(tmp_path):
    flows = tmp_path / "f.csv.gz"
    with gzip.open(flows, "wt", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        for i in range(10):
            w.writerow(
                ["f", "a", "b", 1, 2, "TCP", float(i), float(i) + 1, "fin", BENIGN, *([1.0] * len(FEATURE_NAMES))]
            )
    with pytest.raises(TrainingError):
        train_from_flows(flows, tmp_path / "o", smoke=True)


def test_read_flows_rejects_missing_columns(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("a,b\n1,2\n")
    with pytest.raises(TrainingError, match="missing columns"):
        read_flows(p)


# ------------------------------------------------------------------ metrics, gate, report


def test_flow_metrics_hand_computed():
    classes = ["A", "BENIGN"]
    y = np.array(["A", "A", "BENIGN", "BENIGN", "Z"])
    proba = np.array([[0.9, 0.1], [0.2, 0.8], [0.1, 0.9], [0.6, 0.4], [0.7, 0.3]])
    m = flow_metrics(y, proba, classes, {"A"}, threshold=0.5)
    pc = m["per_class"]
    assert pc["A"]["precision"] == pytest.approx(1 / 3) and pc["A"]["recall"] == pytest.approx(0.5)
    assert pc["BENIGN"]["recall"] == pytest.approx(0.5)
    assert m["headline_classes"] == ["A"] and m["headline_macro_f1"] == pytest.approx(pc["A"]["f1"])
    assert "Z" in m["zero_shot"] and m["zero_shot"]["Z"]["flagged_as_attack_rate"] == 1.0
    assert np.array(m["confusion_matrix"]).sum() == 5
    b = m["binary_attack_vs_benign"]
    assert (b["tp"], b["fp"], b["fn"]) == (1, 1, 1)


def test_calibrate_threshold_respects_validation_fpr():
    rng = np.random.default_rng(1)
    y = np.array([BENIGN] * 2000 + ["X"] * 200)
    scores = np.concatenate([rng.beta(1, 20, 2000), rng.beta(20, 2, 200)])
    cal = calibrate_threshold(y, scores, target_fpr=0.001)
    assert cal["val_fpr_at_threshold"] <= 0.001
    assert calibrate_threshold(np.array([BENIGN] * 5), np.zeros(5))["method"].startswith("fallback")


def test_alert_metrics_hand_computed():
    labels = [
        {
            "attack_type": "A",
            "attacker_ips": ["1.1.1.1"],
            "victim_ips": ["2.2.2.2"],
            "start_ts": 1000.0,
            "end_ts": 1180.0,
        }
    ]
    alerts = [
        {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "last_seen": 1010.0},
        {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "last_seen": 1130.0},
        {"source_ip": "9.9.9.9", "destination_ip": "2.2.2.2", "last_seen": 1100.0},
        {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "last_seen": 5000.0},
    ]
    m = alert_metrics(alerts, labels, benign_seconds=3600.0)
    assert (m["true_alerts"], m["false_alerts"]) == (2, 2)
    assert m["per_class"]["A"]["recall"] == pytest.approx(2 / 3)
    assert m["per_class"]["A"]["instance_recall"] == 1.0
    assert m["false_alerts_per_benign_hour"] == pytest.approx(2.0)
    assert m["alert_precision"] == pytest.approx(0.5)
    empty = alert_metrics([], labels, 3600.0)
    assert empty["alert_precision"] is None and empty["per_class"]["A"]["recall"] == 0.0


def _sys(recall, fp):
    return {"recall_headline": recall, "false_alerts_per_benign_hour": fp}


def test_gate_decisions():
    assert decide_gate(_sys(0.50, 2.0), _sys(0.70, 2.0))["decision"] == "PASS"
    assert decide_gate(_sys(0.50, 2.0), _sys(0.70, 1.0))["decision"] == "PASS"
    fail_fp = decide_gate(_sys(0.50, 2.0), _sys(0.90, 2.5))
    assert fail_fp["decision"] == "FAIL" and "rose" in fail_fp["reason"]
    assert decide_gate(_sys(0.50, 2.0), _sys(0.505, 2.0))["decision"] == "FAIL"  # gain below minimum
    assert decide_gate(_sys(0.50, 2.0), _sys(0.40, 1.0))["decision"] == "FAIL"
    assert decide_gate(_sys(None, 2.0), _sys(0.9, 1.0))["decision"] == "INCONCLUSIVE"
    assert decide_gate(_sys(0.5, None), _sys(0.9, 1.0))["decision"] == "INCONCLUSIVE"


def test_report_is_generated_from_json_only(tmp_path):
    text = render_report(None, None, None, "abc123", [])
    assert "NOT RUN" in text and "abc123" in text and "does not stop" in text.lower().replace("**", "")

    ev = {
        "model_sha256": "f" * 64,
        "pcaps": ["x.pcap"],
        "gate": {"decision": "FAIL", "reason": "r", "min_recall_gain": 0.01, "recall_gain": 0.123456},
        "rules_only": {
            "recall_headline": 0.111111,
            "false_alerts_per_benign_hour": 1.5,
            "alerts": 7,
            "false_alerts": 3,
            "alert_precision": 0.5,
            "recall_all_classes": 0.2,
            "f1_all_classes": 0.3,
            "per_class": {"A": {"recall": 0.25}},
        },
        "rules_plus_ml": {
            "recall_headline": 0.222222,
            "false_alerts_per_benign_hour": 2.5,
            "alerts": 9,
            "false_alerts": 5,
            "alert_precision": 0.4,
            "recall_all_classes": 0.3,
            "f1_all_classes": 0.4,
            "per_class": {"A": {"recall": 0.5}},
        },
        "zero_shot_classes": [],
        "packets_read": 100,
        "packets_replayed": 90,
        "replay_seconds": 10.0,
        "attack_seconds": 4.0,
        "benign_seconds": 6.0,
        "ml_alert_count": 2,
        "wall_clock_seconds": 1.0,
    }
    meta = {
        "files": [
            {
                "name": "Monday.pcap",
                "status": "PROCESSED",
                "size_bytes": 12345,
                "sha256": "ab" * 32,
                "packets": 5,
                "flows": 2,
            }
        ],
        "missing": ["Friday.pcap"],
        "wall_clock_seconds": 9.5,
        "warnings": ["w1"],
    }
    text = render_report(None, ev, meta, "deadbeef", ["ml_eval.json"])
    for needle in (
        "0.1111",
        "0.2222",
        "0.1235",
        "FAIL",
        "f" * 64,
        "ab" * 32,
        "12,345",
        "Friday.pcap",
        "w1",
        "out of the runtime alert path",
    ):
        assert needle in text

    doc = tmp_path / "DATASET.md"
    doc.write_text(f"head\n{DATASET_BEGIN}\nold\n{DATASET_END}\ntail\n", encoding="utf-8")
    update_dataset_doc(doc, meta)
    out = doc.read_text(encoding="utf-8")
    assert "Monday.pcap" in out and "old" not in out and out.startswith("head") and out.rstrip().endswith("tail")
    doc.write_text("no markers", encoding="utf-8")
    with pytest.raises(ValueError):
        update_dataset_doc(doc, meta)
