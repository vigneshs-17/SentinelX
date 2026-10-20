"""
Evaluation scoring and metric calculation for SentinelX intrusion detection benchmarks.
Matches alerts to ground-truth labels by attack type, attacker/victim endpoints, and time overlap.
Generates comprehensive JSON and Markdown reports.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from config.settings import (
    SCAN_TYPE_HORIZONTAL,
    SCAN_TYPE_SLOW,
    SCAN_TYPE_VERTICAL,
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_SYN_FLOOD,
    THREAT_TYPE_VOLUMETRIC,
)
from detection.alert import Alert

DETECTOR_CATEGORIES = [
    "PORT_SCAN (VERTICAL)",
    "PORT_SCAN (HORIZONTAL)",
    "PORT_SCAN (SLOW)",
    "SYN_FLOOD",
    "VOLUMETRIC",
]


def _get_category(item: Alert | dict[str, Any]) -> str:
    """Derives canonical detector category string from an alert or ground truth label."""
    if isinstance(item, Alert):
        threat_type = item.threat_type
        scan_type = item.scan_type
    else:
        threat_type = item.get("threat_type") or item.get("attack_type") or ""
        scan_type = item.get("scan_type")

    if threat_type == THREAT_TYPE_PORT_SCAN:
        if scan_type == SCAN_TYPE_VERTICAL:
            return "PORT_SCAN (VERTICAL)"
        elif scan_type == SCAN_TYPE_HORIZONTAL:
            return "PORT_SCAN (HORIZONTAL)"
        elif scan_type in (SCAN_TYPE_SLOW, "SLOW_VERTICAL", "SLOW_HORIZONTAL", "SLOW"):
            return "PORT_SCAN (SLOW)"
        return "PORT_SCAN"
    elif threat_type == THREAT_TYPE_SYN_FLOOD:
        return "SYN_FLOOD"
    elif threat_type == THREAT_TYPE_VOLUMETRIC:
        return "VOLUMETRIC"
    return str(threat_type)


def _match_alert_to_label(alert: Alert | dict[str, Any], label: dict[str, Any], time_tolerance: float = 60.0) -> bool:
    """
    Checks if an alert matches a ground-truth label by attack type,
    endpoints, and time interval overlap.
    """
    alert_cat = _get_category(alert)
    label_cat = _get_category(label)
    if alert_cat != label_cat:
        return False

    if isinstance(alert, Alert):
        src_ip = alert.source_ip
        dst_ip = alert.destination_ip
        dst_port = alert.destination_port
        alert_ts = alert.last_seen
    else:
        src_ip = alert.get("source_ip")
        dst_ip = alert.get("destination_ip")
        dst_port = alert.get("destination_port")
        alert_ts = float(alert.get("last_seen") or alert.get("ts") or 0.0)

    # 1. Attacker IP match (if specified and not wildcard)
    attacker_ips = label.get("attacker_ips") or []
    if attacker_ips and attacker_ips != ["*"]:
        if src_ip and src_ip not in attacker_ips:
            return False

    # 2. Victim IP match (if specified)
    victim_ip = label.get("victim_ip")
    if victim_ip:
        if dst_ip and dst_ip != victim_ip:
            return False

    # 3. Victim port match (if specified)
    victim_port = label.get("victim_port")
    if victim_port is not None:
        if dst_port is not None and dst_port != victim_port:
            return False

    # 4. Time overlap check
    start_ts = float(label.get("start_ts", 0.0))
    end_ts = float(label.get("end_ts", 0.0))
    if not (start_ts - 1.0 <= alert_ts <= end_ts + time_tolerance):
        return False

    return True


@dataclass
class DetectorMetrics:
    category: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 1.0
    recall: float = 1.0
    f1: float = 1.0
    mean_ttd_seconds: float = 0.0
    max_ttd_seconds: float = 0.0

    def compute(self, ttd_list: list[float]) -> None:
        if self.tp + self.fp > 0:
            self.precision = self.tp / (self.tp + self.fp)
        else:
            self.precision = 1.0 if self.fn == 0 else 0.0

        if self.tp + self.fn > 0:
            self.recall = self.tp / (self.tp + self.fn)
        else:
            self.recall = 1.0

        if self.precision + self.recall > 0:
            self.f1 = (2.0 * self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1 = 1.0 if (self.precision == 1.0 and self.recall == 1.0) else 0.0

        if ttd_list:
            self.mean_ttd_seconds = sum(ttd_list) / len(ttd_list)
            self.max_ttd_seconds = max(ttd_list)
        else:
            self.mean_ttd_seconds = 0.0
            self.max_ttd_seconds = 0.0


@dataclass
class ScenarioEvaluationResult:
    scenario_name: str
    packet_count: int
    duration_seconds: float
    benign_duration_seconds: float
    alerts: list[dict[str, Any]]
    ground_truth: list[dict[str, Any]]
    expected_alerts: list[dict[str, Any]]
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    passed: bool
    failure_reasons: list[str]


def evaluate_scenario(
    scenario_name: str,
    alerts: Sequence[Alert | dict[str, Any]],
    ground_truth: list[dict[str, Any]],
    expected_alerts: list[dict[str, Any]],
    packet_count: int,
    duration_seconds: float,
    benign_duration_seconds: float,
) -> ScenarioEvaluationResult:
    """
    Evaluates a single scenario run against ground truth labels and golden expectations.
    """
    raw_alerts = [a.to_dict() if isinstance(a, Alert) else a for a in alerts]
    failure_reasons: list[str] = []

    # 1. Match alerts with ground truth labels
    matched_label_indices: set[int] = set()
    matched_alert_indices: set[int] = set()

    for l_idx, label in enumerate(ground_truth):
        for a_idx, alert in enumerate(raw_alerts):
            if _match_alert_to_label(alert, label):
                matched_label_indices.add(l_idx)
                matched_alert_indices.add(a_idx)

    tp = len(matched_label_indices)
    fn = len(ground_truth) - tp
    fp = len(raw_alerts) - len(matched_alert_indices)

    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (
        (2.0 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else (1.0 if (precision == 1.0 and recall == 1.0) else 0.0)
    )

    # 2. Check against golden expectations
    # Group actual alerts by category and count
    actual_counts: dict[str, int] = {}
    for alert in raw_alerts:
        cat = _get_category(alert)
        actual_counts[cat] = actual_counts.get(cat, 0) + 1

    expected_counts: dict[str, int] = {}
    for exp in expected_alerts:
        cat = _get_category(exp)
        expected_counts[cat] = expected_counts.get(cat, 0) + int(exp.get("count", 1))

    all_cats = set(actual_counts.keys()).union(set(expected_counts.keys()))
    for cat in sorted(all_cats):
        act = actual_counts.get(cat, 0)
        expected_count = expected_counts.get(cat, 0)
        if act != expected_count:
            failure_reasons.append(f"Category '{cat}' alert count mismatch: expected {expected_count}, got {act}")

    if f1 < 1.0:
        failure_reasons.append(f"Scenario F1 score is {f1:.2f} (< 1.0)")

    passed = len(failure_reasons) == 0

    return ScenarioEvaluationResult(
        scenario_name=scenario_name,
        packet_count=packet_count,
        duration_seconds=duration_seconds,
        benign_duration_seconds=benign_duration_seconds,
        alerts=raw_alerts,
        ground_truth=ground_truth,
        expected_alerts=expected_alerts,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        passed=passed,
        failure_reasons=failure_reasons,
    )


def compute_suite_metrics(
    scenario_results: list[ScenarioEvaluationResult],
    wall_clock_time: float,
) -> dict[str, Any]:
    """
    Aggregates metrics across all scenarios and computes detector-specific breakdowns.
    """
    total_packets = sum(r.packet_count for r in scenario_results)
    total_duration = sum(r.duration_seconds for r in scenario_results)
    total_benign_duration = sum(r.benign_duration_seconds for r in scenario_results)

    detector_metrics: dict[str, DetectorMetrics] = {cat: DetectorMetrics(category=cat) for cat in DETECTOR_CATEGORIES}
    detector_ttd: dict[str, list[float]] = {cat: [] for cat in DETECTOR_CATEGORIES}

    all_alerts: list[dict[str, Any]] = []
    all_labels: list[dict[str, Any]] = []

    for r in scenario_results:
        all_alerts.extend(r.alerts)
        all_labels.extend(r.ground_truth)

    # Compute matches per detector category
    for cat in DETECTOR_CATEGORIES:
        cat_labels = [lbl for lbl in all_labels if _get_category(lbl) == cat]
        cat_alerts = [alt for alt in all_alerts if _get_category(alt) == cat]

        matched_labels: set[int] = set()
        matched_alerts: set[int] = set()

        for l_idx, label in enumerate(cat_labels):
            for a_idx, alert in enumerate(cat_alerts):
                if _match_alert_to_label(alert, label):
                    matched_labels.add(l_idx)
                    matched_alerts.add(a_idx)
                    ttd = max(0.0, float(alert.get("last_seen", 0.0)) - float(label.get("start_ts", 0.0)))
                    detector_ttd[cat].append(ttd)

        dm = detector_metrics[cat]
        dm.tp = len(matched_labels)
        dm.fn = len(cat_labels) - dm.tp
        dm.fp = len(cat_alerts) - len(matched_alerts)
        dm.compute(detector_ttd[cat])

    # Overall suite metrics
    overall_tp = sum(dm.tp for dm in detector_metrics.values())
    overall_fp = sum(dm.fp for dm in detector_metrics.values())
    overall_fn = sum(dm.fn for dm in detector_metrics.values())

    precision = (
        overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else (1.0 if overall_fn == 0 else 0.0)
    )
    recall = overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) > 0 else 1.0
    f1 = (
        (2.0 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else (1.0 if (precision == 1.0 and recall == 1.0) else 0.0)
    )

    benign_hours = total_benign_duration / 3600.0 if total_benign_duration > 0 else 0.0
    false_alerts_per_hour = (overall_fp / benign_hours) if benign_hours > 0 else 0.0
    throughput_pps = (total_packets / wall_clock_time) if wall_clock_time > 0 else 0.0

    all_passed = all(r.passed for r in scenario_results) and f1 >= 1.0

    return {
        "status": "PASS" if all_passed else "FAIL",
        "total_packets": total_packets,
        "total_duration_seconds": total_duration,
        "total_benign_duration_seconds": total_benign_duration,
        "wall_clock_time_seconds": wall_clock_time,
        "throughput_pps": throughput_pps,
        "overall": {
            "tp": overall_tp,
            "fp": overall_fp,
            "fn": overall_fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_alerts_per_benign_hour": false_alerts_per_hour,
        },
        "detectors": {cat: asdict(dm) for cat, dm in detector_metrics.items()},
        "scenarios": [asdict(r) for r in scenario_results],
    }


def generate_markdown_report(suite_summary: dict[str, Any]) -> str:
    """Formats evaluation results as a clean, GitHub-flavored Markdown report."""
    status_badge = "PASS" if suite_summary["status"] == "PASS" else "FAIL"
    overall = suite_summary["overall"]

    lines: list[str] = [
        "# SentinelX Detection Benchmark Report",
        "",
        f"**Benchmark Status**: {status_badge}  ",
        f"**Throughput**: {suite_summary['throughput_pps']:,.1f} packets/sec | **Wall-Clock Time**: {suite_summary['wall_clock_time_seconds']:.2f} s | **Total Packets**: {suite_summary['total_packets']:,}  ",
        f"**Overall F1**: {overall['f1']:.4f} (Precision: {overall['precision']:.4f}, Recall: {overall['recall']:.4f}) | **False Alerts / Benign Hour**: {overall['false_alerts_per_benign_hour']:.2f}",
        "",
        "## Scenario Breakdown",
        "",
        "| Scenario | Packets | Duration (s) | Exp. Alerts | Act. Alerts | TP | FP | FN | F1 | Status |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for s in suite_summary["scenarios"]:
        s_status = "PASS" if s["passed"] else "FAIL"
        lines.append(
            f"| `{s['scenario_name']}` | {s['packet_count']:,} | {s['duration_seconds']:.1f} | "
            f"{len(s['expected_alerts'])} | {len(s['alerts'])} | {s['tp']} | {s['fp']} | {s['fn']} | "
            f"{s['f1']:.2f} | {s_status} |"
        )

    lines.extend(
        [
            "",
            "## Detector Performance",
            "",
            "| Detector | TP | FP | FN | Precision | Recall | F1 Score | Mean TTD (s) | Max TTD (s) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
    )

    for cat, d in suite_summary["detectors"].items():
        lines.append(
            f"| **{cat}** | {d['tp']} | {d['fp']} | {d['fn']} | "
            f"{d['precision']:.4f} | {d['recall']:.4f} | {d['f1']:.4f} | "
            f"{d['mean_ttd_seconds']:.2f} | {d['max_ttd_seconds']:.2f} |"
        )

    lines.extend(
        [
            "",
            "> [!NOTE]",
            "> This benchmark exercises the synthetic regression scenario suite under `eval/`. Real-world accuracy on labeled external datasets is evaluated in Phase 5.",
            "",
        ]
    )

    return "\n".join(lines)


def save_reports(suite_summary: dict[str, Any], out_dir: Path | str) -> tuple[Path, Path]:
    """Writes report.json and report.md into out_dir."""
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    json_file = out_path / "report.json"
    md_file = out_path / "report.md"

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(suite_summary, f, indent=2)

    md_content = generate_markdown_report(suite_summary)
    with open(md_file, "w", encoding="utf-8") as f:
        f.write(md_content)

    return json_file, md_file
