"""
Rules-only vs rules+ML comparison on a held-out test replay, plus the decision gate.

Replays PCAPs (restricted to the test-split time segments when the labels file carries them) through the
detection engine and the flow model in a single pass, so both systems see identical packets:
  rules-only  = engine alerts
  rules+ML    = engine alerts + ML_ANOMALY alerts (ML only ever adds)
Both are scored against the same labelled attack windows with the same metrics (ml/evaluate.py).
"""

from __future__ import annotations

import bisect
import json
import time
from pathlib import Path
from typing import Any

from scapy.all import PcapReader

from capture.packet_parser import parse_packet
from detection.engine import DetectionEngine
from ml.artifact import load_bundle, write_gate
from ml.evaluate import alert_metrics, decide_gate
from ml.model import git_sha
from ml.runtime import MLScorer


def load_eval_labels(path: Path | str) -> dict[str, Any]:
    """Accept the ML test-labels payload (dict) or a plain Phase 4 label list."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, list):
        return {"labels": raw, "segments": None, "trained_classes": None, "zero_shot_classes": []}
    if not isinstance(raw, dict) or "labels" not in raw:
        raise ValueError("labels file must be a JSON list or an object with a 'labels' key")
    raw.setdefault("segments", None)
    raw.setdefault("trained_classes", None)
    raw.setdefault("zero_shot_classes", [])
    return raw


def _union_seconds(intervals: list[tuple[float, float]]) -> float:
    total, cur_end = 0.0, None
    cur_start = 0.0
    for a, b in sorted(intervals):
        if cur_end is None or a > cur_end:
            if cur_end is not None:
                total += cur_end - cur_start
            cur_start, cur_end = a, b
        else:
            cur_end = max(cur_end, b)
    if cur_end is not None:
        total += cur_end - cur_start
    return total


def run_ml_comparison(
    pcaps: list[Path | str],
    labels_path: Path | str,
    model_dir: Path | str,
    out_dir: Path | str = "eval_output",
    write_gate_file: bool = True,
    min_recall_gain: float = 0.01,
) -> dict[str, Any]:
    paths = [Path(p).resolve() for p in pcaps]
    for p in paths:
        if not p.is_file():
            raise FileNotFoundError(f"PCAP file not found: {p}")
    spec = load_eval_labels(labels_path)
    labels: list[dict[str, Any]] = spec["labels"]
    bundle = load_bundle(model_dir, require_gate=False)
    smoke = json.loads(bundle.get("meta_json", "{}")).get("mode") == "smoke"

    seg_by_file: dict[str, list[tuple[float, float]]] = {}
    if spec["segments"] is not None:
        for s in spec["segments"]:
            seg_by_file.setdefault(s["file"], []).append((float(s["start_ts"]), float(s["end_ts"])))
        for v in seg_by_file.values():
            v.sort()

    if seg_by_file:  # replay chronologically: the engine's event clock never moves backwards
        paths.sort(key=lambda p: seg_by_file[p.name][0][0] if p.name in seg_by_file else float("inf"))

    engine = DetectionEngine()
    scorer = MLScorer(bundle)
    rule_alerts: list[dict[str, Any]] = []
    ml_alerts: list[dict[str, Any]] = []
    n_packets = n_replayed = 0
    min_ts: float | None = None
    max_ts: float | None = None
    wall = time.perf_counter()

    for p in paths:
        segs = seg_by_file.get(p.name) if spec["segments"] is not None else None
        if spec["segments"] is not None and not segs:
            continue
        starts = [s[0] for s in segs] if segs else []
        with PcapReader(str(p)) as reader:
            for pkt in reader:
                n_packets += 1
                ts = float(getattr(pkt, "time", 0.0))
                if segs:
                    i = bisect.bisect_right(starts, ts) - 1
                    if i < 0 or ts > segs[i][1]:
                        continue
                n_replayed += 1
                min_ts = ts if min_ts is None else min(min_ts, ts)
                max_ts = ts if max_ts is None else max(max_ts, ts)
                data = parse_packet(pkt)
                for a in engine.process_packet(data):
                    d = a.to_dict()
                    rule_alerts.append(d)
                    scorer.note_rule_alert(d)
                ml_alerts.extend(scorer.observe(data))
    ml_alerts.extend(scorer.flush())
    wall_clock = time.perf_counter() - wall

    if spec["segments"] is not None:
        replay_seconds = sum(b - a for f, v in seg_by_file.items() if f in {p.name for p in paths} for a, b in v)
    else:
        replay_seconds = (max_ts - min_ts) if (min_ts is not None and max_ts is not None) else 0.0
    attack_seconds = _union_seconds([(float(x["start_ts"]), float(x["end_ts"])) for x in labels])
    benign_seconds = max(0.0, replay_seconds - attack_seconds)

    label_classes = {str(x.get("attack_type")) for x in labels}
    trained = (
        set(spec["trained_classes"]) if spec["trained_classes"] is not None else set(bundle.get("trained_classes", []))
    )
    headline = label_classes & trained if trained else label_classes
    zero_shot = sorted(label_classes - headline)

    rules = alert_metrics(rule_alerts, labels, benign_seconds, headline)
    hybrid = alert_metrics(rule_alerts + ml_alerts, labels, benign_seconds, headline)
    ml_only = alert_metrics(ml_alerts, labels, benign_seconds, headline)
    gate = decide_gate(rules, hybrid, min_recall_gain)
    if smoke:
        gate = {
            **gate,
            "decision": "UNVERIFIED_SMOKE",
            "reason": "smoke model trained on synthetic scenarios; never eligible for the alert path",
        }

    summary = {
        "git_sha": git_sha(),
        "model_sha256": bundle["model_sha256"],
        "pcaps": [p.name for p in paths],
        "packets_read": n_packets,
        "packets_replayed": n_replayed,
        "replay_seconds": replay_seconds,
        "attack_seconds": attack_seconds,
        "benign_seconds": benign_seconds,
        "wall_clock_seconds": wall_clock,
        "headline_classes": sorted(headline),
        "zero_shot_classes": zero_shot,
        "rules_only": rules,
        "rules_plus_ml": hybrid,
        "ml_alerts_only": ml_only,
        "ml_alert_count": len(ml_alerts),
        "gate": gate,
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ml_eval.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if write_gate_file:
        write_gate(model_dir, {**gate, "git_sha": summary["git_sha"]})
    return summary
