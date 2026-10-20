"""
Evaluation runner for SentinelX.
Executes synthetic scenarios or external labelled PCAP benchmarks through DetectionEngine,
computes precision/recall/F1 metrics, and writes JSON/Markdown reports.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from scapy.all import PcapReader

from capture.packet_parser import parse_packet
from detection.engine import DetectionEngine
from eval.scenarios import SCENARIO_NAMES, generate_scenario
from eval.score import (
    ScenarioEvaluationResult,
    compute_suite_metrics,
    evaluate_scenario,
    save_reports,
)


def load_expected_alerts() -> dict[str, list[dict[str, Any]]]:
    """Loads the golden expectations file."""
    expected_file = Path(__file__).parent / "expected.json"
    if not expected_file.exists():
        return {}
    with open(expected_file, encoding="utf-8") as f:
        return json.load(f)


def run_scenario_benchmark(
    scenario_names: list[str] | str = "all",
    out_dir: Path | str = "eval_output",
    seed: int = 42,
) -> dict[str, Any]:
    """
    Runs the scenario evaluation benchmark against the specified scenario names.
    Compares alerts with expected.json and ground truth labels.
    """
    if scenario_names == "all" or scenario_names == ["all"]:
        target_scenarios = list(SCENARIO_NAMES)
    elif isinstance(scenario_names, str):
        target_scenarios = [s.strip() for s in scenario_names.split(",") if s.strip()]
    else:
        target_scenarios = list(scenario_names)

    expected_map = load_expected_alerts()
    scenario_results: list[ScenarioEvaluationResult] = []

    wall_start = time.perf_counter()

    for name in target_scenarios:
        print(f"[*] Running evaluation scenario: {name}...")
        packets, ground_truth, meta = generate_scenario(name, seed=seed)

        # Process packets through a dedicated DetectionEngine instance
        engine = DetectionEngine()
        alerts = []
        for pkt in packets:
            data = parse_packet(pkt)
            triggered = engine.process_packet(data)
            if triggered:
                alerts.extend(triggered)

        expected = expected_map.get(name, [])
        result = evaluate_scenario(
            scenario_name=name,
            alerts=alerts,
            ground_truth=ground_truth,
            expected_alerts=expected,
            packet_count=len(packets),
            duration_seconds=meta["duration_seconds"],
            benign_duration_seconds=meta["benign_duration_seconds"],
        )
        scenario_results.append(result)

    wall_clock_time = time.perf_counter() - wall_start
    summary = compute_suite_metrics(scenario_results, wall_clock_time=wall_clock_time)

    # Save output artifacts
    save_reports(summary, out_dir)

    return summary


def run_external_pcap_benchmark(
    pcap_path: Path | str,
    labels_path: Path | str,
    out_dir: Path | str = "eval_output",
) -> dict[str, Any]:
    """
    Evaluates an external labelled PCAP file against ground truth labels.
    """
    pcap_file = Path(pcap_path).resolve()
    labels_file = Path(labels_path).resolve()

    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
    if not labels_file.exists():
        raise FileNotFoundError(f"Labels file not found: {labels_file}")

    with open(labels_file, encoding="utf-8") as f:
        ground_truth: list[dict[str, Any]] = json.load(f)

    print(f"[*] Replaying external PCAP: {pcap_file}...")
    wall_start = time.perf_counter()

    engine = DetectionEngine()
    alerts = []
    packet_count = 0
    min_ts: float | None = None
    max_ts: float | None = None

    with PcapReader(str(pcap_file)) as reader:
        for pkt in reader:
            packet_count += 1
            pkt_time = float(getattr(pkt, "time", 0.0))
            if min_ts is None or pkt_time < min_ts:
                min_ts = pkt_time
            if max_ts is None or pkt_time > max_ts:
                max_ts = pkt_time

            data = parse_packet(pkt)
            triggered = engine.process_packet(data)
            if triggered:
                alerts.extend(triggered)

    wall_clock_time = time.perf_counter() - wall_start
    duration = (max_ts - min_ts) if (min_ts is not None and max_ts is not None) else 0.0

    result = evaluate_scenario(
        scenario_name=pcap_file.stem,
        alerts=alerts,
        ground_truth=ground_truth,
        expected_alerts=[],
        packet_count=packet_count,
        duration_seconds=duration,
        benign_duration_seconds=duration,
    )

    summary = compute_suite_metrics([result], wall_clock_time=wall_clock_time)
    save_reports(summary, out_dir)

    return summary
