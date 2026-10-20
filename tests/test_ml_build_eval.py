"""scripts/build_flows.py, the rules-only vs rules+ML replay, and the train/eval CLI."""

import csv
import gzip
import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scapy.all import wrpcap

import main as main_mod
import ml.artifact as artifact
from eval.ml_compare import run_ml_comparison
from eval.scenarios import DEFAULT_BASE_TS, generate_scenario
from ml.artifact import ModelSecurityError, load_bundle
from ml.build import build_scenario_flows, window_warnings
from ml.dataset import load_schedule

KEY = "build-eval-test-key-0123456789"
SMALL = [
    "benign_web_browsing",
    "benign_lan_noise",
    "fast_vertical_scan",
    "horizontal_sweep",
    "slow_scan",
    "syn_flood_spoofed",
]
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_flows.py"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv(artifact.KEY_ENV, KEY)


def load_script():
    spec = importlib.util.spec_from_file_location("build_flows_script", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _schedule_for_scan(tmp_path, wrong_attacker=False):
    start = datetime.fromtimestamp(DEFAULT_BASE_TS, tz=UTC)
    hh = start.hour
    path = tmp_path / "schedule.json"
    path.write_text(
        json.dumps(
            {
                "utc_offset_hours": 0,
                "attacker_aliases": [],
                "windows": [
                    {
                        "date": start.strftime("%Y-%m-%d"),
                        "class": "TestScan",
                        "start": f"{hh:02d}:{start.minute:02d}",
                        "end": f"{hh:02d}:{start.minute + 1:02d}" if start.minute < 59 else f"{hh:02d}:59",
                        "attackers": ["203.0.113.9" if wrong_attacker else "198.51.100.50"],
                        "victims": ["192.168.1.100"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_build_flows_script_labels_from_schedule_and_records_hashes(tmp_path):
    pcap = tmp_path / "scan.pcap"
    wrpcap(str(pcap), generate_scenario("fast_vertical_scan")[0])
    out = tmp_path / "flows.csv.gz"
    rc = load_script().main(
        [str(pcap), str(tmp_path / "ghost.pcap"), "--schedule", str(_schedule_for_scan(tmp_path)), "--out", str(out)]
    )
    assert rc == 0
    with gzip.open(out, "rt", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 30 and {r["label"] for r in rows} == {"TestScan"}
    assert all(r["file"] == "scan.pcap" for r in rows)
    meta = json.loads(Path(str(out) + ".meta.json").read_text())
    ok = next(f for f in meta["files"] if f["name"] == "scan.pcap")
    assert ok["sha256"] == hashlib.sha256(pcap.read_bytes()).hexdigest() and ok["size_bytes"] == pcap.stat().st_size
    assert meta["missing"] == ["ghost.pcap"]
    assert next(f for f in meta["files"] if f["name"] == "ghost.pcap")["status"] == "MISSING"


def test_all_files_missing_exits_nonzero_and_invents_nothing(tmp_path):
    out = tmp_path / "flows.csv.gz"
    rc = load_script().main(
        [str(tmp_path / "a.pcap"), "--out", str(out), "--schedule", str(_schedule_for_scan(tmp_path))]
    )
    assert rc == 2
    with gzip.open(out, "rt", encoding="utf-8") as fh:
        assert len(fh.read().strip().splitlines()) == 1  # header only


def test_window_labelling_nothing_is_flagged_by_warnings(tmp_path):
    from ml.build import build_flows

    pcap = tmp_path / "scan.pcap"
    wrpcap(str(pcap), generate_scenario("fast_vertical_scan")[0])
    windows = load_schedule(_schedule_for_scan(tmp_path, wrong_attacker=True))
    meta = build_flows([pcap], windows, tmp_path / "o.csv.gz")
    assert meta["files"][0]["label_counts"] == {"BENIGN": 30}  # right time, wrong addresses -> nothing labelled
    warnings = window_warnings(windows, meta)
    assert len(warnings) == 1 and "labelled 0 flows" in warnings[0]
    good = load_schedule(_schedule_for_scan(tmp_path))
    assert window_warnings(good, build_flows([pcap], good, tmp_path / "p.csv.gz")) == []


def test_cli_train_smoke_then_replay_compare_never_enables_ml(tmp_path, monkeypatch, capsys):
    flows = tmp_path / "flows.csv.gz"
    build_scenario_flows(SMALL, flows)
    model_dir = tmp_path / "models"
    args = main_mod.parse_arguments(["train", "--flows", str(flows), "--out", str(model_dir), "--smoke"])
    main_mod.handle_train(args)
    assert (model_dir / "flow_model.skops").exists() and (model_dir / "flow_model.skops.sig").exists()

    packets, labels, _ = generate_scenario("mixed")
    pcap, lab = tmp_path / "mixed.pcap", tmp_path / "labels.json"
    wrpcap(str(pcap), packets)
    lab.write_text(json.dumps(labels), encoding="utf-8")
    summary = run_ml_comparison([pcap], lab, model_dir, tmp_path / "out")
    assert summary["packets_replayed"] == summary["packets_read"] > 0
    assert summary["gate"]["decision"] == "UNVERIFIED_SMOKE"  # smoke models can never pass
    assert summary["rules_only"]["alerts"] > 0
    assert summary["rules_plus_ml"]["alerts"] == summary["rules_only"]["alerts"] + summary["ml_alert_count"]
    assert summary["rules_plus_ml"]["recall_all_classes"] >= summary["rules_only"]["recall_all_classes"]  # ML only adds
    assert (tmp_path / "out" / "ml_eval.json").exists()
    with pytest.raises(ModelSecurityError, match="not PASS"):
        load_bundle(model_dir, require_gate=True)

    # CLI wiring
    argv = [
        "eval",
        "--pcap",
        str(pcap),
        "--labels",
        str(lab),
        "--ml-model",
        str(model_dir),
        "--out",
        str(tmp_path / "o2"),
    ]
    monkeypatch.setattr("sys.argv", ["main.py", *argv])
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 0 and "UNVERIFIED_SMOKE" in capsys.readouterr().out


def test_replay_restricts_to_test_segments(tmp_path):
    flows = tmp_path / "flows.csv.gz"
    build_scenario_flows(SMALL, flows)
    model_dir = tmp_path / "m"
    main_mod.handle_train(
        main_mod.parse_arguments(["train", "--flows", str(flows), "--out", str(model_dir), "--smoke"])
    )
    packets, labels, meta = generate_scenario("mixed")
    pcap = tmp_path / "mixed.pcap"
    wrpcap(str(pcap), packets)
    t0 = DEFAULT_BASE_TS
    spec = tmp_path / "labels.json"
    spec.write_text(
        json.dumps(
            {
                "labels": [
                    {
                        "attack_type": "PORT_SCAN",
                        "attacker_ips": ["*"],
                        "victim_ips": ["*"],
                        "start_ts": t0,
                        "end_ts": t0 + 60,
                    }
                ],
                "segments": [{"file": "mixed.pcap", "start_ts": t0, "end_ts": t0 + 60}],
                "trained_classes": ["PORT_SCAN"],
                "zero_shot_classes": [],
            }
        ),
        encoding="utf-8",
    )
    s = run_ml_comparison([pcap], spec, model_dir, tmp_path / "o", write_gate_file=False)
    assert 0 < s["packets_replayed"] < s["packets_read"]
    assert s["replay_seconds"] == 60.0 and s["attack_seconds"] == 60.0 and s["benign_seconds"] == 0.0
    assert s["gate"]["decision"] == "UNVERIFIED_SMOKE"
    with pytest.raises(FileNotFoundError):
        run_ml_comparison([tmp_path / "nope.pcap"], spec, model_dir, tmp_path / "o")
