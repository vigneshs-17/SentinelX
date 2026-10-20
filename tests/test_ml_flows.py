"""Flow extractor against hand-built packet sequences, plus train/serve feature parity."""

import csv
import gzip
from pathlib import Path

import numpy as np
import pytest

from capture.packet_parser import parse_packet
from eval.scenarios import _build_tcp_packet, _build_udp_packet
from ml.build import COLUMNS, extract_labelled
from ml.flows import FEATURE_NAMES, FlowExtractor, canonical_key, dst_port_class
from ml.runtime import MLScorer

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
C, S = "10.0.0.1", "10.0.0.2"


def pkt(ts, src, dst, sport, dport, flags=0, size=60, proto="TCP"):
    return {
        "ts": ts,
        "source_ip": src,
        "destination_ip": dst,
        "source_port": sport,
        "destination_port": dport,
        "protocol": proto,
        "packet_size": size,
        "tcp_flags": flags,
    }


def handshake(t0, sport=40000, dport=80):
    return [
        pkt(t0, C, S, sport, dport, SYN),
        pkt(t0 + 0.01, S, C, dport, sport, SYN | ACK),
        pkt(t0 + 0.02, C, S, sport, dport, ACK),
    ]


def feats(flow):
    return flow.feature_dict()


def test_feature_schema_has_no_raw_identifiers_and_is_documented():
    assert len(FEATURE_NAMES) <= 25
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    banned = {"src_ip", "dst_ip", "src_port", "dst_port", "source_ip", "destination_ip", "port", "ip"}
    assert not banned & set(FEATURE_NAMES)
    doc = (Path(__file__).resolve().parent.parent / "docs" / "ML_FEATURES.md").read_text(encoding="utf-8")
    for name in FEATURE_NAMES:
        assert f"`{name}`" in doc, f"{name} missing from docs/ML_FEATURES.md"


def test_canonical_key_is_direction_independent_and_port_classes():
    assert canonical_key(C, S, 1234, 80, "TCP") == canonical_key(S, C, 80, 1234, "TCP")
    assert (dst_port_class(80), dst_port_class(8080), dst_port_class(55000)) == (0, 1, 2)


def test_full_tcp_session_with_handshake_and_fin():
    ex = FlowExtractor()
    seq = handshake(100.0) + [
        pkt(100.10, C, S, 40000, 80, ACK | PSH, 200),
        pkt(100.20, S, C, 80, 40000, ACK | PSH, 1000),
        pkt(100.30, C, S, 40000, 80, FIN | ACK),
        pkt(100.40, S, C, 80, 40000, FIN | ACK),
        pkt(100.50, C, S, 40000, 80, ACK),
    ]
    out = []
    for p in seq:
        out += ex.process(p)
    assert out == []  # still open until timeout/flush
    # an unrelated packet 20 s later advances event time past the idle timeout
    out += ex.process(pkt(120.0, "9.9.9.9", "8.8.8.8", 5000, 53, proto="UDP"))
    assert len(out) == 1
    f = out[0]
    d = feats(f)
    assert f.end_reason == "fin"
    assert (f.src_ip, f.dst_ip, f.dst_port) == (C, S, 80)
    assert d["handshake_completed"] == 1.0
    assert (d["fwd_packets"], d["bwd_packets"]) == (5, 3)
    assert (d["fwd_bytes"], d["bwd_bytes"]) == (60 + 60 + 200 + 60 + 60, 60 + 1000 + 60)
    assert d["syn_count"] == 2 and d["fin_count"] == 2 and d["psh_count"] == 2 and d["rst_count"] == 0
    assert d["duration"] == pytest.approx(0.5)
    assert d["dst_port_class"] == 0 and d["is_tcp"] == 1.0
    assert d["bytes_per_s"] == pytest.approx((d["fwd_bytes"] + d["bwd_bytes"]) / 0.5)
    assert d["packets_per_s"] == pytest.approx(8 / 0.5)


def test_rst_closes_flow_and_new_syn_starts_new_flow():
    ex = FlowExtractor()
    out = []
    for p in handshake(10.0) + [pkt(10.1, S, C, 80, 40000, RST | ACK)]:
        out += ex.process(p)
    assert out == []
    out += ex.process(pkt(10.5, C, S, 40000, 80, SYN))  # same 5-tuple reused
    assert len(out) == 1 and out[0].end_reason == "rst"
    assert feats(out[0])["rst_count"] == 1.0
    out += ex.flush()
    assert len(out) == 2 and out[1].end_reason == "flush"


def test_idle_timeout_splits_flow_on_same_key():
    ex = FlowExtractor(idle_timeout=15.0)
    out = ex.process(pkt(0.0, C, S, 1111, 53, proto="UDP"))
    out += ex.process(pkt(1.0, S, C, 53, 1111, proto="UDP"))
    out += ex.process(pkt(20.0, C, S, 1111, 53, proto="UDP"))  # 19 s gap > 15 s
    assert len(out) == 1 and out[0].end_reason == "idle"
    assert feats(out[0])["is_tcp"] == 0.0 and feats(out[0])["handshake_completed"] == 0.0
    assert len(ex.flush()) == 1


def test_active_timeout_caps_flow_duration():
    ex = FlowExtractor(active_timeout=120.0, idle_timeout=15.0)
    out = []
    for i in range(0, 140, 10):  # a packet every 10 s keeps the flow active
        out += ex.process(pkt(float(i), C, S, 2222, 443, ACK))
    assert len(out) == 1 and out[0].end_reason == "active"
    assert out[0].end_ts - out[0].start_ts <= 120.0


def test_bounded_table_evicts_oldest_and_emits_it():
    ex = FlowExtractor(max_flows=2)
    out = []
    for i in range(3):
        out += ex.process(pkt(float(i), C, S, 3000 + i, 80, SYN))
    assert ex.table_size == 2 and ex.evictions == 1
    assert len(out) == 1 and out[0].end_reason == "evicted" and out[0].src_port == 3000
    assert len(ex.flush()) == 2


def test_table_never_exceeds_cap_under_spoofed_source_churn():
    ex = FlowExtractor(max_flows=100)
    emitted = 0
    for i in range(5000):
        emitted += len(ex.process(pkt(i * 0.001, f"10.{i // 250}.{i % 250}.1", S, 4000, 80, SYN)))
        assert ex.table_size <= 100
    assert emitted + len(ex.flush()) == 5000


def test_first_packet_defines_forward_direction_and_unusable_packets_are_skipped():
    ex = FlowExtractor()
    ex.process(pkt(1.0, S, C, 80, 40000, SYN | ACK))  # capture started mid-handshake
    ex.process(pkt(1.1, C, S, 40000, 80, ACK))
    ex.process({"ts": None, "protocol": "TCP"})
    ex.process({"ts": 1.0, "protocol": "OTHER", "source_ip": C, "destination_ip": S})
    (f,) = ex.flush()
    assert f.src_ip == S and feats(f)["handshake_completed"] == 0.0
    assert ex.packets_skipped == 2


def test_length_and_iat_statistics_match_numpy():
    ex = FlowExtractor()
    sizes, times = [60, 100, 1500, 40], [0.0, 0.5, 0.6, 2.6]
    for s, t in zip(sizes, times, strict=True):
        ex.process(pkt(t, C, S, 5000, 9999, 0, s, "UDP"))
    (f,) = ex.flush()
    d = feats(f)
    iats = np.diff(times)
    assert d["pkt_len_mean"] == pytest.approx(np.mean(sizes))
    assert d["pkt_len_std"] == pytest.approx(np.std(sizes))
    assert d["pkt_len_max"] == 1500
    assert d["iat_mean"] == pytest.approx(np.mean(iats))
    assert d["iat_std"] == pytest.approx(np.std(iats))
    assert d["dst_port_class"] == 1.0


def test_per_source_context_counts_unique_ports_and_hosts():
    ex = FlowExtractor()
    for i, port in enumerate([21, 22, 23, 80, 443]):
        ex.process(pkt(float(i), C, S, 6000 + i, port, SYN))
    ex.process(pkt(5.5, C, "10.0.0.3", 6100, 80, SYN))
    flows = ex.flush()
    last = max(flows, key=lambda f: f.start_ts)
    d = feats(last)
    assert d["src_unique_dst_ports_60s"] == 5.0  # 21,22,23,80,443 (80 repeats on a second host)
    assert d["src_unique_dst_hosts_60s"] == 2.0


def test_context_ignores_events_older_than_60_seconds():
    ex = FlowExtractor()
    out = ex.process(pkt(0.0, C, S, 7000, 21, SYN))
    out += ex.process(pkt(100.0, C, S, 7001, 22, SYN))
    flows = sorted(out + ex.flush(), key=lambda f: f.start_ts)
    assert feats(flows[1])["src_unique_dst_ports_60s"] == 1.0


class _StubModel:
    classes_ = np.array(["BENIGN", "X"])

    def __init__(self):
        self.seen = []

    def predict_proba(self, x):
        self.seen.append(np.array(x))
        return np.tile([0.9, 0.1], (len(x), 1))


def test_train_serve_feature_parity(tmp_path):
    """Same packets through the training path (CSV rows) and the serving path (scorer input) give identical vectors."""
    scapy_packets = []
    t = 1_790_000_000.0
    for sport, dport in [(40001, 80), (40002, 443), (40003, 22)]:
        scapy_packets.append(_build_tcp_packet(C, S, sport, dport, "S", t))
        scapy_packets.append(_build_tcp_packet(S, C, dport, sport, "SA", t + 0.01, ack=1))
        scapy_packets.append(_build_tcp_packet(C, S, sport, dport, "A", t + 0.02, seq=1, ack=1))
        scapy_packets.append(_build_tcp_packet(C, S, sport, dport, "PA", t + 0.05, payload=b"x" * 300))
        scapy_packets.append(_build_tcp_packet(C, S, sport, dport, "FA", t + 0.30))
        scapy_packets.append(_build_udp_packet(C, "10.0.0.9", 5353, 5353, t + 0.1, payload=b"q" * 20))
        t += 2.0

    out = tmp_path / "f.csv.gz"
    with gzip.open(out, "wt", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        extract_labelled("parity", scapy_packets, [], w)
    with gzip.open(out, "rt", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    train_vectors = [[float(r[n]) for n in FEATURE_NAMES] for r in rows]

    stub = _StubModel()
    scorer = MLScorer(
        {
            "model": stub,
            "classes": ["BENIGN", "X"],
            "benign_label": "BENIGN",
            "threshold": 0.5,
            "medium_threshold": 0.75,
        }
    )
    for p in scapy_packets:
        scorer.observe(parse_packet(p))
    scorer.flush()
    serve_vectors = np.vstack(stub.seen).tolist()
    assert len(train_vectors) == len(serve_vectors) > 0
    assert train_vectors == serve_vectors
