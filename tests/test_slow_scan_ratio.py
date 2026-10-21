"""Slow horizontal scan: failures must dominate the attempts, so slow browsing no longer alerts every minute."""

import pytest

from capture.packet_parser import parse_packet
from config.settings import validate_config
from detection.engine import DetectionEngine
from eval.scenarios import generate_scenario

CLIENT = "2409:40f4:2013:6428:5189:4555:6426:7405"


def pkt(ts, src, sport, dst, dport, flags):
    return {
        "ts": ts,
        "source_ip": src,
        "destination_ip": dst,
        "protocol": "TCP",
        "source_port": sport,
        "destination_port": dport,
        "packet_size": 60,
        "tcp_syn": flags == "S",
        "tcp_syn_ack": flags == "SA",
        "tcp_ack": flags in ("A", "RA"),
        "tcp_rst": flags in ("R", "RA"),
    }


def run(engine, packets):
    alerts = []
    for p in packets:
        alerts.extend(engine.process_packet(p))
    return alerts


def host(i):
    return f"2606:4700:{i:x}::443"


def attempts(n, complete_every=0, per_host_completions=0, step=5.0, start=1000.0):
    """n hosts, one every `step` s. complete_every=k: every k-th host completes its handshake. per_host_completions
    adds that many extra completed connections to other hosts before each probe (dilution by an attacker)."""
    out, t, extra = [], start, 10_000
    for i in range(n):
        for _ in range(per_host_completions):
            out += [
                pkt(t, CLIENT, 30000 + extra, host(extra), 443, "S"),
                pkt(t + 0.02, host(extra), 443, CLIENT, 30000 + extra, "SA"),
                pkt(t + 0.04, CLIENT, 30000 + extra, host(extra), 443, "A"),
            ]
            extra += 1
            t += 0.1
        sport = 40000 + i
        out.append(pkt(t, CLIENT, sport, host(i), 443, "S"))
        if complete_every and i % complete_every == 0:
            out += [pkt(t + 0.02, host(i), 443, CLIENT, sport, "SA"), pkt(t + 0.04, CLIENT, sport, host(i), 443, "A")]
        t += step
    return out


def slow_horizontal(alerts):
    return [a for a in alerts if a.scan_type == "SLOW_HORIZONTAL"]


@pytest.mark.parametrize("name", ["benign_slow_browsing_ipv6", "benign_background_apps"])
def test_slow_browsing_scenarios_raise_no_alert(name):
    packets, labels, _ = generate_scenario(name)
    distinct = {parse_packet(p)["destination_ip"] for p in packets if parse_packet(p)["tcp_syn"]}
    assert labels == [] and len(distinct) >= 50  # 50+ distinct hosts on 443, IPv4 and IPv6
    assert run(DetectionEngine(), [parse_packet(p) for p in packets]) == []


def test_slow_horizontal_scan_of_unanswered_syns_is_detected_with_its_failure_ratio():
    alerts = slow_horizontal(run(DetectionEngine(), attempts(30)))
    assert len(alerts) == 1
    ev = alerts[0].evidence
    assert ev["failure_ratio"] == 1.0 and ev["unique_targets_observed"] >= 20 and ev["hosts_tried"] >= 20


def test_slow_scan_with_some_completed_connections_is_still_detected():
    """One host in ten completes (an open port that accepted a full connect): 90% failures, above the 80% bar."""
    assert len(slow_horizontal(run(DetectionEngine(), attempts(40, complete_every=10)))) >= 1


def test_known_limit_scan_diluted_with_completed_connections_is_not_detected():
    """Trade-off: an attacker who completes three real connections per probe hides in the browsing noise."""
    alerts = run(DetectionEngine(), attempts(40, per_host_completions=3))
    assert slow_horizontal(alerts) == []


def test_ratio_threshold_is_configurable():
    diluted = attempts(40, per_host_completions=1)  # ~50% failures
    assert slow_horizontal(run(DetectionEngine(), diluted)) == []
    permissive = DetectionEngine(config={"SLOW_SCAN_MIN_FAILURE_RATIO": 0.4})
    assert len(slow_horizontal(run(permissive, diluted))) >= 1


def test_recent_host_tables_stay_bounded():
    engine = DetectionEngine()
    run(engine, attempts(300, step=0.5))
    entries = [v for _, v in engine.state_store.get_partition("slow_scan").items_snapshot() if "seen" in v]
    cap = engine.config.get("SLOW_SCAN_THRESHOLD", 20) * 3
    assert entries and all(len(v["seen"]) <= cap and len(v["targets"]) <= cap for v in entries)


@pytest.mark.parametrize("bad", [0, 0.0, 1.5, -0.1, "high"])
def test_config_rejects_a_bad_failure_ratio(bad):
    with pytest.raises(ValueError, match="SLOW_SCAN_MIN_FAILURE_RATIO"):
        validate_config({"SLOW_SCAN_MIN_FAILURE_RATIO": bad})
