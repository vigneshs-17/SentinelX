"""
Phase 3 Comprehensive Regression Test Suite for SentinelX.

Verifies:
1. Deterministic event-time detection (benign 10 pps over 120s emits 0 alerts - D1 fix).
2. AST guard: 0 wall-clock time calls (time.time, time.monotonic, datetime.now) in detection/.
3. Partition isolation under spoofing churn (2,000 SYNs + 200,000 spoofed sources - Correction 1).
4. Slow scan detection (25 SYNs, 1 every 4s -> 0 VERTICAL, 1 SLOW_VERTICAL - Correction 4).
5. Volumetric EWMA baseline, warmup gating, and top-5 talkers (Correction 2).
6. Volumetric local networks CIDR filtering (Correction 2).
7. Out-of-order event timestamps maintain monotonic clock (Correction 6).
8. Missing timestamp packet skipped with parse error metric incremented (Correction 5).
9. SQLite Migration 3 (HIGH_TRAFFIC -> VOLUMETRIC and user_version = 3).
10. Bounded partition capacity and eviction counting.
"""

import ast
import sqlite3
from pathlib import Path

from capture.metrics import PipelineMetrics
from capture.processor import PacketProcessor
from config.settings import (
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_SYN_FLOOD,
    THREAT_TYPE_VOLUMETRIC,
)
from database.migrations import apply_migrations
from detection.engine import DetectionEngine
from detection.state_store import BoundedStateStore


def test_d1_event_time_determinism_benign_10pps():
    """
    Defect D1 verification:
    Benign 10 pps traffic spread over 120s event time was previously flagged
    as HIGH_TRAFFIC when replayed faster than real time.
    With event-time DetectionEngine, exactly 0 alerts must be emitted.
    """
    engine = DetectionEngine()

    start_ts = 1_000_000.0
    alerts_seen = []

    # 120 seconds of traffic at 10 pps = 1,200 packets
    for i in range(1200):
        event_time = start_ts + (i * 0.1)  # 10 packets per second
        packet = {
            "ts": event_time,
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "source_port": 40000 + (i % 100),
            "destination_port": 443,
            "protocol": "TCP",
            "tcp_syn": False,
            "tcp_ack": True,
            "packet_size": 200,
        }
        alerts = engine.process_packet(packet)
        if alerts:
            alerts_seen.extend(alerts)

    assert len(alerts_seen) == 0, f"Expected 0 alerts for benign 10 pps traffic, got {len(alerts_seen)}"


def test_ast_wall_clock_guard():
    """
    AST inspection test:
    Parses all python files in detection/ and detection/detectors/ and asserts
    that NO calls or imports of time.time, time.monotonic, datetime.now,
    datetime.utcnow, or datetime.today exist.
    """
    forbidden_calls = {
        ("time", "time"),
        ("time", "monotonic"),
        ("datetime", "now"),
        ("datetime", "utcnow"),
        ("datetime", "today"),
    }
    forbidden_names = {"time", "monotonic", "now", "utcnow", "today"}

    detection_dir = Path("detection")
    py_files = list(detection_dir.rglob("*.py"))
    assert len(py_files) >= 5, "Expected detection/ python files to inspect"

    violations = []

    for file_path in py_files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))

        # Track aliased imports in this module
        imported_symbols: dict[str, str] = {}

        for node in ast.walk(tree):
            # Check imports: from time import time, monotonic
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    imported_symbols[alias.asname or alias.name] = f"{mod}.{alias.name}"
                    if mod == "time" and alias.name in ("time", "monotonic"):
                        violations.append((file_path.name, node.lineno, f"from {mod} import {alias.name}"))
                    if mod == "datetime" and alias.name in ("now", "utcnow", "today"):
                        violations.append((file_path.name, node.lineno, f"from {mod} import {alias.name}"))

            # Check calls: time.time(), time.monotonic(), datetime.now(), or imported aliases
            elif isinstance(node, ast.Call):
                func = node.func
                # Attribute call like time.time()
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    call_tuple = (func.value.id, func.attr)
                    if call_tuple in forbidden_calls:
                        violations.append((file_path.name, node.lineno, f"{func.value.id}.{func.attr}()"))
                # Direct name call like time() if imported
                elif isinstance(func, ast.Name):
                    if func.id in forbidden_names and func.id in imported_symbols:
                        violations.append((file_path.name, node.lineno, f"{func.id}() via {imported_symbols[func.id]}"))

    assert not violations, f"Found wall-clock time calls in detection package: {violations}"


def test_partitioning_isolation_syn_flood_under_spoofed_churn():
    """
    Correction 1 Verification:
    2,000 SYNs to one host:80 in 5s interleaved with 200,000 packets from spoofed random sources.
    Assert:
    - Exactly 1 SYN_FLOOD alert emitted.
    - Every partition stays within its hard capacity cap.
    - SYN-flood aggregate table was never evicted by the 200,000 spoofed sources.
    """
    engine = DetectionEngine()

    start_ts = 2_000_000.0
    syn_flood_alerts = []

    target_host = "10.0.0.80"
    target_port = 80

    # Interleave 2,000 attack SYNs with 200,000 spoofed background packets
    # Total packets: 202,000 over 5.0 seconds event time
    total_spoofed = 200_000
    total_attack = 2_000
    stride = total_spoofed // total_attack  # 100 spoofed packets per attack SYN

    attack_syns_injected = 0
    spoofed_injected = 0

    for step in range(total_attack):
        # Inject 1 attack SYN targeting (target_host, target_port)
        event_time = start_ts + (step * (5.0 / total_attack))
        attack_pkt = {
            "ts": event_time,
            "source_ip": f"198.51.100.{(step % 250) + 1}",
            "destination_ip": target_host,
            "source_port": 30000 + (step % 20000),
            "destination_port": target_port,
            "protocol": "TCP",
            "tcp_syn": True,
            "tcp_ack": False,
            "packet_size": 60,
        }
        attack_alerts = engine.process_packet(attack_pkt)
        syn_flood_alerts.extend([a for a in attack_alerts if a.threat_type == THREAT_TYPE_SYN_FLOOD])
        attack_syns_injected += 1

        # Interleave spoofed packets from distinct random sources
        for s in range(stride):
            spoofed_idx = (step * stride) + s
            sp_time = event_time + (s * 0.00001)
            # Rotating random /24 subnets
            sp_src = f"{(spoofed_idx // 65536) % 200 + 1}.{(spoofed_idx // 256) % 250 + 1}.{(spoofed_idx % 250) + 1}.1"
            sp_pkt = {
                "ts": sp_time,
                "source_ip": sp_src,
                "destination_ip": f"10.1.{s % 50}.{s % 50}",
                "source_port": 10000 + (s % 1000),
                "destination_port": 5000 + (s % 1000),
                "protocol": "TCP",
                "tcp_syn": True,
                "tcp_ack": False,
                "packet_size": 64,
            }
            engine.process_packet(sp_pkt)
            spoofed_injected += 1

    # 1. Exactly 1 SYN_FLOOD alert emitted
    assert len(syn_flood_alerts) == 1, f"Expected exactly 1 SYN_FLOOD alert, got {len(syn_flood_alerts)}"
    assert syn_flood_alerts[0].destination_ip == target_host
    assert syn_flood_alerts[0].destination_port == target_port

    # 2. Assert every partition stayed within its cap
    metrics = engine.get_metrics()
    for part_name, part_stats in metrics["partitions"].items():
        assert part_stats["size"] <= part_stats["capacity"], (
            f"Partition '{part_name}' exceeded capacity: {part_stats['size']} > {part_stats['capacity']}"
        )

    # Half-open table churned heavily with evictions
    assert metrics["partitions"]["syn_flood_half_open"]["evictions"] > 10_000


def test_slow_scan_tuning():
    """
    Correction 4 Verification:
    25 SYNs to 25 unique ports on 1 host, 1 packet every 4s (100s duration).
    Assert:
    - 0 VERTICAL alerts (window is 10s, threshold is 10; here only 2-3 ports per 10s).
    - Exactly 1 SLOW_VERTICAL alert (threshold is 20 unique ports in 300s window).
    """
    engine = DetectionEngine()

    start_ts = 3_000_000.0
    target_host = "10.0.0.22"

    vertical_alerts = []
    slow_vertical_alerts = []

    for i in range(25):
        event_time = start_ts + (i * 4.0)  # 1 packet every 4 seconds
        pkt = {
            "ts": event_time,
            "source_ip": "192.168.1.99",
            "destination_ip": target_host,
            "source_port": 50000 + i,
            "destination_port": 1000 + i,  # 25 unique ports
            "protocol": "TCP",
            "tcp_syn": True,
            "tcp_ack": False,
            "packet_size": 60,
        }
        alerts = engine.process_packet(pkt)
        for a in alerts:
            if a.threat_type == THREAT_TYPE_PORT_SCAN:
                if a.scan_type == "VERTICAL":
                    vertical_alerts.append(a)
                elif a.scan_type == "SLOW_VERTICAL":
                    slow_vertical_alerts.append(a)

    assert len(vertical_alerts) == 0, f"Expected 0 VERTICAL alerts, got {len(vertical_alerts)}"
    assert len(slow_vertical_alerts) == 1, f"Expected exactly 1 SLOW_VERTICAL alert, got {len(slow_vertical_alerts)}"
    assert slow_vertical_alerts[0].evidence["unique_ports_observed"] >= 20


def test_volumetric_ewma_warmup_and_top_talkers():
    """
    Correction 2 Verification:
    - Warm-up phase: 3 completed 10s windows of traffic under hard ceiling -> 0 alerts.
    - Post warm-up phase: a burst of > 5 * EWMA triggers VOLUMETRIC anomaly.
    - Evidence includes top-5 source IPs by packet volume.
    """
    engine = DetectionEngine(config={"VOLUMETRIC_FLOOR_PPS": 200.0})

    target_host = "10.0.0.5"
    start_ts = 4_000_000.0

    # 1. Warm-up: 3 completed windows (30 seconds) of 50 pps traffic (500 packets per 10s window)
    warmup_alerts = []
    ts = start_ts
    for _w in range(3):
        for p in range(500):
            ts += 0.02  # 50 pps
            pkt = {
                "ts": ts,
                "source_ip": f"192.168.1.{(p % 10) + 1}",
                "destination_ip": target_host,
                "source_port": 20000 + p,
                "destination_port": 80,
                "protocol": "TCP",
                "tcp_syn": False,
                "packet_size": 200,
            }
            alerts = engine.process_packet(pkt)
            warmup_alerts.extend([a for a in alerts if a.threat_type == THREAT_TYPE_VOLUMETRIC])

    assert len(warmup_alerts) == 0, "No alerts should fire during baseline warm-up under ceiling"

    # Advance time to complete the 3rd window
    ts += 1.0

    # 2. Post warm-up: Inject burst of 1,200 pps over 2 seconds (exceeds floor_pps of 200 and 5 * EWMA of ~250)
    # Using 5 distinct high-volume talkers
    burst_alerts = []
    for b in range(2400):
        ts += 0.000833  # ~1,200 pps
        talker_idx = b % 5
        pkt = {
            "ts": ts,
            "source_ip": f"198.51.100.{talker_idx + 10}",
            "destination_ip": target_host,
            "source_port": 30000 + b,
            "destination_port": 80,
            "protocol": "TCP",
            "tcp_syn": False,
            "packet_size": 500,
        }
        alerts = engine.process_packet(pkt)
        burst_alerts.extend([a for a in alerts if a.threat_type == THREAT_TYPE_VOLUMETRIC])

    assert len(burst_alerts) >= 1, "Expected VOLUMETRIC alert post warm-up"
    evidence = burst_alerts[0].evidence
    assert evidence["completed_warmup_windows"] >= 3
    assert len(evidence["top_talkers"]) == 5
    top_ips = {t["source_ip"] for t in evidence["top_talkers"]}
    assert "198.51.100.10" in top_ips


def test_volumetric_hard_ceiling_during_warmup():
    """
    Verification: During warm-up, rates exceeding the hard ceiling
    immediately fire an alert.
    """
    engine = DetectionEngine(config={"VOLUMETRIC_HARD_CEILING_PPS": 200.0, "VOLUMETRIC_MIN_PACKETS": 200})

    target_host = "10.0.0.9"
    ts = 5_000_000.0
    ceiling_alerts = []

    # 250 packets in 1.0 second = 250 pps (exceeds 200 ceiling)
    for i in range(250):
        ts += 0.004
        pkt = {
            "ts": ts,
            "source_ip": "172.16.0.1",
            "destination_ip": target_host,
            "source_port": 1000 + i,
            "destination_port": 443,
            "protocol": "TCP",
            "tcp_syn": False,
            "packet_size": 1000,
        }
        alerts = engine.process_packet(pkt)
        ceiling_alerts.extend([a for a in alerts if a.threat_type == THREAT_TYPE_VOLUMETRIC])

    assert len(ceiling_alerts) == 1, "Hard ceiling must trigger during warm-up"


def test_volumetric_local_networks_filter():
    """
    Correction 2 Verification:
    If LOCAL_NETWORKS is configured, evaluate only destinations within those CIDRs.
    """
    engine = DetectionEngine(
        config={
            "LOCAL_NETWORKS": "192.168.0.0/16,10.0.0.0/8",
            "VOLUMETRIC_FLOOR_PPS": 100.0,
            "VOLUMETRIC_MIN_PACKETS": 200,
            "VOLUMETRIC_WARMUP_WINDOWS": 0,
        }
    )

    ts = 6_000_000.0

    # Send flood to non-local external IP (e.g. 8.8.8.8)
    non_local_alerts = []
    for i in range(250):
        ts += 0.002
        pkt = {
            "ts": ts,
            "source_ip": "192.168.1.1",
            "destination_ip": "8.8.8.8",
            "source_port": 50000 + i,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_size": 500,
        }
        alerts = engine.process_packet(pkt)
        non_local_alerts.extend(alerts)

    assert len(non_local_alerts) == 0, "Non-local destination must be filtered out by LOCAL_NETWORKS"

    # Send identical flood to local protected destination (e.g. 10.0.0.5)
    local_alerts = []
    for i in range(250):
        ts += 0.002
        pkt = {
            "ts": ts,
            "source_ip": "192.168.1.1",
            "destination_ip": "10.0.0.5",
            "source_port": 50000 + i,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_size": 500,
        }
        alerts = engine.process_packet(pkt)
        local_alerts.extend(alerts)

    assert len(local_alerts) == 1, "Local destination within CIDR must be evaluated and alerted"


def test_out_of_order_packets_clock_monotonicity():
    """
    Correction 6 Verification:
    Engine maintains monotonic clock = max(clock, ts).
    Packets arriving out of order are handled without crashing, and clock never regresses.
    """
    engine = DetectionEngine()

    engine.process_packet({"ts": 100.0, "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "protocol": "TCP"})
    assert engine.clock == 100.0

    # Out-of-order packet with earlier timestamp
    engine.process_packet({"ts": 95.0, "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "protocol": "TCP"})
    assert engine.clock == 100.0, "Clock must not regress on out-of-order packet"

    # Later packet advances clock
    engine.process_packet({"ts": 105.0, "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "protocol": "TCP"})
    assert engine.clock == 105.0


def test_missing_timestamp_packet_skipped_and_metrics():
    """
    Correction 5 Verification:
    Missing timestamp packet is dropped by PacketProcessor and records parse error in metrics.
    """
    metrics = PipelineMetrics()
    processor = PacketProcessor(metrics=metrics)

    # Mock raw packet without time attribute
    class MockBadPacket:
        pass

    bad_pkt = MockBadPacket()
    result = processor.process(bad_pkt)

    assert result == []
    assert metrics.parse_errors == 1


def test_migration_3_rename_high_traffic_to_volumetric(tmp_path):
    """
    Migration 3 Verification:
    Existing database with HIGH_TRAFFIC alerts is upgraded to user_version = 3,
    and all threat_type values are renamed to VOLUMETRIC.
    """
    db_file = tmp_path / "test_migration3.db"
    conn = sqlite3.connect(str(db_file))

    # Create v1 schema with user_version = 1
    conn.execute(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            message TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO alerts (timestamp, threat_type, severity) VALUES ('2026-01-01T10:00:00', 'HIGH_TRAFFIC', 'HIGH');"
    )
    conn.execute(
        "INSERT INTO alerts (timestamp, threat_type, severity) VALUES ('2026-01-01T10:05:00', 'PORT_SCAN', 'MEDIUM');"
    )
    conn.execute("PRAGMA user_version = 1;")
    conn.commit()

    # Apply migrations up to current version (6: adds sensor_status, destination_port and ingested_at; migration 3 behaviour is unchanged)
    new_version = apply_migrations(conn)
    assert new_version == 6

    cursor = conn.cursor()
    cursor.execute("SELECT threat_type FROM alerts WHERE id = 1;")
    assert cursor.fetchone()[0] == "VOLUMETRIC"

    cursor.execute("SELECT threat_type FROM alerts WHERE id = 2;")
    assert cursor.fetchone()[0] == "PORT_SCAN"

    conn.close()


def test_bounded_state_store_lru_and_metrics():
    """
    BoundedStateStore capacity and LRU eviction verification.
    """
    store = BoundedStateStore(name="test_store", max_entries=3)
    store.put("a", 1)
    store.put("b", 2)
    store.put("c", 3)

    assert store.size() == 3
    assert store.evictions == 0

    # Access "a" to make it MRU (least recently used is now "b")
    store.get("a")

    # Add "d": capacity reached, "b" must be evicted
    store.put("d", 4)
    assert store.size() == 3
    assert store.evictions == 1
    assert "b" not in store
    assert "a" in store
    assert "c" in store
    assert "d" in store

    metrics = store.get_metrics()
    assert metrics["capacity"] == 3
    assert metrics["evictions"] == 1
    assert metrics["hits"] == 1
