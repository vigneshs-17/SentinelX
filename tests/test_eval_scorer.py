"""
Comprehensive unit test suite for the evaluation scorer and scenario generator.
Tests cover:
  1. Deterministic byte-identical PCAP generation for the same seed.
  2. Scorer evaluation: TP, FP, FN, partial time overlap, multiple attacks from same IP.
  3. Golden expectation verification and failure reporting.
"""

import hashlib
import tempfile
from pathlib import Path

from scapy.all import wrpcap

from config.settings import (
    PORT_SCAN_TIME_WINDOW,
    SLOW_SCAN_TIME_WINDOW,
    SYN_FLOOD_TIME_WINDOW,
    VOLUMETRIC_TIME_WINDOW,
)
from eval.scenarios import (
    DEFAULT_BASE_TS,
    SCENARIO_NAMES,
    generate_scenario,
)
from eval.score import (
    _match_alert_to_label,
    compute_suite_metrics,
    evaluate_scenario,
    generate_markdown_report,
    get_detector_tolerance,
)


def test_scenario_generation_deterministic_byte_identity():
    """Verify that scenario generation produces byte-identical PCAP output for the same seed."""
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        pcap1 = dir_path / "run1.pcap"
        pcap2 = dir_path / "run2.pcap"

        pkts1, lbls1, _ = generate_scenario("fast_vertical_scan", seed=12345)
        pkts2, lbls2, _ = generate_scenario("fast_vertical_scan", seed=12345)

        assert len(pkts1) == len(pkts2)
        assert lbls1 == lbls2

        wrpcap(str(pcap1), pkts1)
        wrpcap(str(pcap2), pkts2)

        sha1 = hashlib.sha256(pcap1.read_bytes()).hexdigest()
        sha2 = hashlib.sha256(pcap2.read_bytes()).hexdigest()

        assert sha1 == sha2, "Generated PCAP files with identical seeds must be byte-identical!"


def test_all_scenario_names_registered():
    """Verify all 9 mandatory benchmark scenarios are defined and callable."""
    expected_scenarios = [
        "benign_web_browsing",
        "benign_bulk_download",
        "benign_lan_noise",
        "fast_vertical_scan",
        "horizontal_sweep",
        "slow_scan",
        "syn_flood_spoofed",
        "udp_flood_inbound",
        "mixed",
    ]
    assert sorted(SCENARIO_NAMES) == sorted(expected_scenarios)
    for name in expected_scenarios:
        pkts, lbls, meta = generate_scenario(name, seed=42)
        assert len(pkts) > 0
        assert "duration_seconds" in meta
        assert "benign_duration_seconds" in meta


def test_scorer_true_positive():
    """Verify single alert matching ground truth results in TP=1, FP=0, FN=0, F1=1.0."""
    ground_truth = [
        {
            "attack_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "attacker_ips": ["198.51.100.50"],
            "victim_ip": "192.168.1.100",
            "victim_port": None,
            "start_ts": 1000.0,
            "end_ts": 1005.0,
        }
    ]
    alerts = [
        {
            "threat_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "source_ip": "198.51.100.50",
            "destination_ip": "192.168.1.100",
            "destination_port": 80,
            "first_seen": 1000.0,
            "last_seen": 1004.0,
        }
    ]
    expected = [{"threat_type": "PORT_SCAN", "scan_type": "VERTICAL", "count": 1}]

    res = evaluate_scenario(
        scenario_name="test_tp",
        alerts=alerts,
        ground_truth=ground_truth,
        expected_alerts=expected,
        packet_count=50,
        duration_seconds=10.0,
        benign_duration_seconds=0.0,
    )

    assert res.tp == 1
    assert res.fp == 0
    assert res.fn == 0
    assert res.precision == 1.0
    assert res.recall == 1.0
    assert res.f1 == 1.0
    assert res.passed is True


def test_scorer_false_positive():
    """Verify alert without matching ground truth results in FP=1, TP=0, precision=0.0."""
    ground_truth: list[dict] = []
    alerts = [
        {
            "threat_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "source_ip": "198.51.100.50",
            "destination_ip": "192.168.1.100",
            "destination_port": 80,
            "first_seen": 1000.0,
            "last_seen": 1004.0,
        }
    ]
    expected: list[dict] = []

    res = evaluate_scenario(
        scenario_name="test_fp",
        alerts=alerts,
        ground_truth=ground_truth,
        expected_alerts=expected,
        packet_count=50,
        duration_seconds=10.0,
        benign_duration_seconds=10.0,
    )

    assert res.tp == 0
    assert res.fp == 1
    assert res.fn == 0
    assert res.precision == 0.0
    assert res.passed is False


def test_scorer_false_negative():
    """Verify ground truth attack without alert results in FN=1, TP=0, recall=0.0."""
    ground_truth = [
        {
            "attack_type": "SYN_FLOOD",
            "scan_type": None,
            "attacker_ips": ["*"],
            "victim_ip": "192.168.1.100",
            "victim_port": 80,
            "start_ts": 1000.0,
            "end_ts": 1005.0,
        }
    ]
    alerts: list[dict] = []
    expected = [{"threat_type": "SYN_FLOOD", "count": 1}]

    res = evaluate_scenario(
        scenario_name="test_fn",
        alerts=alerts,
        ground_truth=ground_truth,
        expected_alerts=expected,
        packet_count=50,
        duration_seconds=10.0,
        benign_duration_seconds=0.0,
    )

    assert res.tp == 0
    assert res.fp == 0
    assert res.fn == 1
    assert res.recall == 0.0
    assert res.passed is False


def test_scorer_detector_tolerances_match_windows():
    """Verify that get_detector_tolerance reads exact window constants from config."""
    assert get_detector_tolerance("PORT_SCAN (VERTICAL)") == float(PORT_SCAN_TIME_WINDOW)
    assert get_detector_tolerance("PORT_SCAN (HORIZONTAL)") == float(PORT_SCAN_TIME_WINDOW)
    assert get_detector_tolerance("PORT_SCAN (SLOW)") == float(SLOW_SCAN_TIME_WINDOW)
    assert get_detector_tolerance("SYN_FLOOD") == float(SYN_FLOOD_TIME_WINDOW)
    assert get_detector_tolerance("VOLUMETRIC") == float(VOLUMETRIC_TIME_WINDOW)


def test_scorer_boundary_within_window_is_tp():
    """Verify alert at end_ts + window - 0.1s matches ground truth as a True Positive."""
    window = float(PORT_SCAN_TIME_WINDOW)
    start_ts = DEFAULT_BASE_TS
    end_ts = DEFAULT_BASE_TS + 10.0
    label = {
        "attack_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "attacker_ips": ["198.51.100.50"],
        "victim_ip": "192.168.1.100",
        "victim_port": None,
        "start_ts": start_ts,
        "end_ts": end_ts,
    }
    alert = {
        "threat_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "source_ip": "198.51.100.50",
        "destination_ip": "192.168.1.100",
        "destination_port": 80,
        "first_seen": start_ts,
        "last_seen": end_ts + window - 0.1,
    }
    assert _match_alert_to_label(alert, label) is True

    res = evaluate_scenario(
        scenario_name="test_boundary_tp",
        alerts=[alert],
        ground_truth=[label],
        expected_alerts=[{"threat_type": "PORT_SCAN", "scan_type": "VERTICAL", "count": 1}],
        packet_count=50,
        duration_seconds=end_ts - start_ts + window,
        benign_duration_seconds=0.0,
    )
    assert res.tp == 1
    assert res.fp == 0
    assert res.fn == 0
    assert res.precision == 1.0
    assert res.recall == 1.0
    assert res.f1 == 1.0
    assert res.passed is True


def test_scorer_boundary_outside_window_is_fp_and_fn():
    """Verify alert at end_ts + window + 0.1s is outside window, yielding 1 FP and 1 FN."""
    window = float(PORT_SCAN_TIME_WINDOW)
    start_ts = DEFAULT_BASE_TS
    end_ts = DEFAULT_BASE_TS + 10.0
    label = {
        "attack_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "attacker_ips": ["198.51.100.50"],
        "victim_ip": "192.168.1.100",
        "victim_port": None,
        "start_ts": start_ts,
        "end_ts": end_ts,
    }
    alert = {
        "threat_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "source_ip": "198.51.100.50",
        "destination_ip": "192.168.1.100",
        "destination_port": 80,
        "first_seen": start_ts,
        "last_seen": end_ts + window + 0.1,
    }
    assert _match_alert_to_label(alert, label) is False

    res = evaluate_scenario(
        scenario_name="test_boundary_late",
        alerts=[alert],
        ground_truth=[label],
        expected_alerts=[{"threat_type": "PORT_SCAN", "scan_type": "VERTICAL", "count": 1}],
        packet_count=50,
        duration_seconds=end_ts - start_ts + window + 5.0,
        benign_duration_seconds=0.0,
    )
    assert res.tp == 0
    assert res.fp == 1
    assert res.fn == 1
    assert res.passed is False


def test_scorer_boundary_before_start_is_fp():
    """Verify alert before start_ts - 1.0s does not match and is counted as a False Positive."""
    start_ts = DEFAULT_BASE_TS
    end_ts = DEFAULT_BASE_TS + 10.0
    label = {
        "attack_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "attacker_ips": ["198.51.100.50"],
        "victim_ip": "192.168.1.100",
        "victim_port": None,
        "start_ts": start_ts,
        "end_ts": end_ts,
    }
    alert = {
        "threat_type": "PORT_SCAN",
        "scan_type": "VERTICAL",
        "source_ip": "198.51.100.50",
        "destination_ip": "192.168.1.100",
        "destination_port": 80,
        "first_seen": start_ts - 2.0,
        "last_seen": start_ts - 1.1,
    }
    assert _match_alert_to_label(alert, label) is False

    res = evaluate_scenario(
        scenario_name="test_boundary_early",
        alerts=[alert],
        ground_truth=[],
        expected_alerts=[],
        packet_count=50,
        duration_seconds=end_ts - start_ts,
        benign_duration_seconds=end_ts - start_ts,
    )
    assert res.tp == 0
    assert res.fp == 1
    assert res.fn == 0
    assert res.passed is False


def test_scorer_two_attacks_same_ip():
    """Verify two attacks from the same IP at different timestamps match their respective labels."""
    attacker_ip = "198.51.100.50"
    victim_ip = "192.168.1.100"

    ground_truth = [
        {
            "attack_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "attacker_ips": [attacker_ip],
            "victim_ip": victim_ip,
            "victim_port": None,
            "start_ts": 100.0,
            "end_ts": 105.0,
        },
        {
            "attack_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "attacker_ips": [attacker_ip],
            "victim_ip": victim_ip,
            "victim_port": None,
            "start_ts": 500.0,
            "end_ts": 505.0,
        },
    ]

    alerts = [
        {
            "threat_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "source_ip": attacker_ip,
            "destination_ip": victim_ip,
            "destination_port": 80,
            "first_seen": 100.0,
            "last_seen": 104.0,
        },
        {
            "threat_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "source_ip": attacker_ip,
            "destination_ip": victim_ip,
            "destination_port": 443,
            "first_seen": 500.0,
            "last_seen": 504.0,
        },
    ]

    expected = [{"threat_type": "PORT_SCAN", "scan_type": "VERTICAL", "count": 2}]

    res = evaluate_scenario(
        scenario_name="test_two_attacks_same_ip",
        alerts=alerts,
        ground_truth=ground_truth,
        expected_alerts=expected,
        packet_count=100,
        duration_seconds=600.0,
        benign_duration_seconds=500.0,
    )

    assert res.tp == 2
    assert res.fp == 0
    assert res.fn == 0
    assert res.precision == 1.0
    assert res.recall == 1.0
    assert res.f1 == 1.0
    assert res.passed is True


def test_suite_metrics_and_markdown_rendering():
    """Verify compute_suite_metrics and generate_markdown_report produce valid summary and tables."""
    ground_truth = [
        {
            "attack_type": "VOLUMETRIC",
            "scan_type": None,
            "attacker_ips": ["*"],
            "victim_ip": "192.168.1.100",
            "victim_port": 80,
            "start_ts": 1000.0,
            "end_ts": 1005.0,
        }
    ]
    alerts = [
        {
            "threat_type": "VOLUMETRIC",
            "scan_type": None,
            "source_ip": "198.51.100.1",
            "destination_ip": "192.168.1.100",
            "first_seen": 1000.0,
            "last_seen": 1002.0,
        }
    ]
    expected = [{"threat_type": "VOLUMETRIC", "count": 1}]

    res = evaluate_scenario(
        scenario_name="volumetric_sample",
        alerts=alerts,
        ground_truth=ground_truth,
        expected_alerts=expected,
        packet_count=1000,
        duration_seconds=10.0,
        benign_duration_seconds=5.0,
    )

    summary = compute_suite_metrics([res], wall_clock_time=0.5)
    assert summary["status"] == "PASS"
    assert summary["overall"]["f1"] == 1.0
    assert summary["throughput_pps"] == 2000.0

    md = generate_markdown_report(summary)
    assert "# SentinelX Detection Benchmark Report" in md
    assert "| `volumetric_sample` |" in md
    assert "**VOLUMETRIC**" in md
