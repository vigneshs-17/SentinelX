"""Scan detectors count a destination only when the connection attempt did not complete a handshake."""

import pytest

from capture.packet_parser import parse_packet
from detection.engine import DetectionEngine
from eval.scenarios import generate_scenario

CLIENT4 = "192.168.1.20"
CLIENT6 = "2409:40f4:2013:6428:5189:4555:6426:7405"
HOSTS4 = [f"203.0.113.{i}" for i in range(10, 22)]
HOSTS6 = [f"64:ff9b::284f:{0x8D00 + i:x}" for i in range(12)]


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


def browse(client, hosts, start=1000.0, step=0.5):
    """Complete three-way handshake to every host on 443, one every `step` seconds."""
    out = []
    for i, host in enumerate(hosts):
        t, sport = start + i * step, 40000 + i
        out += [
            pkt(t, client, sport, host, 443, "S"),
            pkt(t + 0.03, host, 443, client, sport, "SA"),
            pkt(t + 0.06, client, sport, host, 443, "A"),
        ]
    return out


def probe(client, hosts, reply=None, start=1000.0, step=0.5):
    """SYN to every host on 443; reply is None (unanswered) or 'RA' (a closed port answers RST/ACK)."""
    out = []
    for i, host in enumerate(hosts):
        t, sport = start + i * step, 40000 + i
        out.append(pkt(t, client, sport, host, 443, "S"))
        if reply:
            out.append(pkt(t + 0.02, host, 443, client, sport, reply))
    return out


@pytest.mark.parametrize(("client", "hosts"), [(CLIENT4, HOSTS4), (CLIENT6, HOSTS6)])
def test_12_hosts_on_443_with_completed_handshakes_raise_no_alert(client, hosts):
    assert run(DetectionEngine(), browse(client, hosts)) == []


@pytest.mark.parametrize(("client", "hosts"), [(CLIENT4, HOSTS4), (CLIENT6, HOSTS6)])
def test_12_hosts_on_443_with_unanswered_syns_raise_horizontal(client, hosts):
    alerts = run(DetectionEngine(), probe(client, hosts))
    assert [a.scan_type for a in alerts] == ["HORIZONTAL"]
    assert alerts[0].source_ip == client


@pytest.mark.parametrize(("client", "hosts"), [(CLIENT4, HOSTS4), (CLIENT6, HOSTS6)])
def test_12_hosts_answered_by_rst_raise_horizontal(client, hosts):
    """A router answering RST for closed ports is still a scan: RST is not a completed handshake."""
    alerts = run(DetectionEngine(), probe(client, hosts, reply="RA"))
    assert [a.scan_type for a in alerts] == ["HORIZONTAL"]


def test_half_open_scan_of_open_ports_is_still_detected():
    """Half-open SYN scan: the open port answers SYN-ACK, the scanner never sends the final ACK (it sends RST)."""
    packets = []
    for i, host in enumerate(HOSTS4):
        t, sport = 1000.0 + i * 0.2, 41000 + i
        packets += [
            pkt(t, CLIENT4, sport, host, 443, "S"),
            pkt(t + 0.02, host, 443, CLIENT4, sport, "SA"),
            pkt(t + 0.04, CLIENT4, sport, host, 443, "R"),
        ]
    assert [a.scan_type for a in run(DetectionEngine(), packets)] == ["HORIZONTAL"]


def test_scan_from_a_browsing_host_is_still_found():
    """Completed handshakes neither use up the threshold nor hide unanswered probes from the same source."""
    probes = probe(CLIENT4, [f"198.51.100.{i}" for i in range(1, 13)], start=1006.0, step=0.1)
    packets = sorted(browse(CLIENT4, HOSTS4) + probes, key=lambda p: p["ts"])
    assert [a.scan_type for a in run(DetectionEngine(), packets)] == ["HORIZONTAL"]


def test_vertical_completed_handshakes_to_many_ports_raise_no_alert():
    packets = []
    for i, port in enumerate(range(8000, 8015)):
        t, sport = 1000.0 + i * 0.2, 42000 + i
        packets += [
            pkt(t, CLIENT4, sport, "203.0.113.5", port, "S"),
            pkt(t + 0.02, "203.0.113.5", port, CLIENT4, sport, "SA"),
            pkt(t + 0.04, CLIENT4, sport, "203.0.113.5", port, "A"),
        ]
    assert run(DetectionEngine(), packets) == []


def test_vertical_rst_answered_ports_are_detected():
    packets = []
    for i, port in enumerate(range(8000, 8015)):
        t, sport = 1000.0 + i * 0.2, 42000 + i
        packets += [
            pkt(t, CLIENT4, sport, "203.0.113.5", port, "S"),
            pkt(t + 0.02, "203.0.113.5", port, CLIENT4, sport, "RA"),
        ]
    assert [a.scan_type for a in run(DetectionEngine(), packets)] == ["VERTICAL"]


def test_slow_vertical_ignores_completed_handshakes_but_finds_unanswered_ones():
    def slow(complete):
        packets = []
        for i in range(25):
            t, sport, port = 1000.0 + i * 5.0, 43000 + i, 9000 + i
            packets.append(pkt(t, CLIENT4, sport, "203.0.113.7", port, "S"))
            if complete:
                packets += [
                    pkt(t + 0.02, "203.0.113.7", port, CLIENT4, sport, "SA"),
                    pkt(t + 0.04, CLIENT4, sport, "203.0.113.7", port, "A"),
                ]
        return run(DetectionEngine(), packets)

    assert slow(complete=True) == []
    assert [a.scan_type for a in slow(complete=False)] == ["SLOW_VERTICAL"]


def test_slow_horizontal_ignores_completed_handshakes():
    packets = []
    for i in range(25):
        host, t, sport = f"203.0.113.{i + 1}", 1000.0 + i * 5.0, 44000 + i
        packets += [
            pkt(t, CLIENT4, sport, host, 443, "S"),
            pkt(t + 0.02, host, 443, CLIENT4, sport, "SA"),
            pkt(t + 0.04, CLIENT4, sport, host, 443, "A"),
        ]
    assert run(DetectionEngine(), packets) == []


def test_tracker_state_is_bounded():
    engine = DetectionEngine(partition_caps={"scan_attempts": 50, "scan_completed": 50})
    for i in range(500):
        run(engine, browse(CLIENT4, [f"10.9.{i // 250}.{i % 250 + 1}"], start=1000.0 + i * 0.01))
    parts = engine.get_metrics()["partitions"]
    assert parts["scan_attempts"]["size"] <= 50 and parts["scan_completed"]["size"] <= 50
    assert parts["scan_completed"]["evictions"] > 0


def test_same_input_gives_same_alerts():
    """The tracker adds no time source: results depend only on packet timestamps."""
    packets = probe(CLIENT4, HOSTS4)
    first = [a.scan_type for a in run(DetectionEngine(), packets)]
    second = [a.scan_type for a in run(DetectionEngine(), packets)]
    assert first == second == ["HORIZONTAL"]


# ------------------------------------------------------------------ scenarios


def test_many_tabs_scenario_exceeds_the_host_threshold_but_every_handshake_completes():
    packets, labels, _ = generate_scenario("benign_many_tabs_browsing")
    assert labels == []
    events = [parse_packet(p) for p in packets]
    assert any(p.haslayer("IPv6") for p in packets) and any(p.haslayer("IP") for p in packets)
    syn_targets = {(e["source_ip"], e["destination_ip"]) for e in events if e["tcp_syn"]}
    assert len(syn_targets) >= 28  # 14 hosts on 443 from each of the two clients, over the threshold of 10
    assert run(DetectionEngine(), events) == []


def test_single_fast_vertical_scan_gives_exactly_one_vertical_alert_per_source_destination_pair():
    packets, _, _ = generate_scenario("fast_vertical_scan")
    alerts = run(DetectionEngine(), [parse_packet(p) for p in packets])
    vertical = [a for a in alerts if a.scan_type == "VERTICAL"]
    assert len(vertical) == len({(a.source_ip, a.destination_ip) for a in vertical}) == 1
    assert len(alerts) == 1  # and no duplicate slow-vertical alert for the same scan
