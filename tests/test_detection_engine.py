"""
Comprehensive test suite for Phase 3 Detection Engine.

Tests stateful Vertical Port Scan, Horizontal Port Scan, Slow Scan,
SYN Flood, Volumetric Anomaly, Cooldowns, and State Store Partitioning
using event-time timestamps.
"""

from config.settings import (
    HORIZONTAL_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW,
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_VOLUMETRIC,
    VERTICAL_SCAN_THRESHOLD,
)
from detection.engine import DetectionEngine


class TestDetectionEngine:
    """Comprehensive test suite for Phase 3 Detection Engine."""

    # =========================================================================
    # 1. VERTICAL PORT SCAN TESTS
    # =========================================================================

    def test_vertical_port_scan_detection(self):
        """Probing >= 10 unique ports on a single host triggers a VERTICAL PORT_SCAN alert."""
        engine = DetectionEngine()
        source_ip = "192.168.1.100"
        target_ip = "192.168.1.10"
        alert = None

        for i, port in enumerate(range(1, VERTICAL_SCAN_THRESHOLD + 1)):
            packet_data = {
                "ts": 1000.0 + (i * 0.1),
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            results = engine.process_packet(packet_data)
            for res in results:
                if res.threat_type == THREAT_TYPE_PORT_SCAN and res.scan_type == "VERTICAL":
                    alert = res.to_dict()

        assert alert is not None
        assert alert["threat_type"] == THREAT_TYPE_PORT_SCAN
        assert alert["scan_type"] == "VERTICAL"
        assert alert["severity"] in ("MEDIUM", "HIGH")
        assert alert["source_ip"] == source_ip
        assert alert["destination_ip"] == target_ip
        assert alert["destination_port_count"] >= VERTICAL_SCAN_THRESHOLD
        assert 0.70 <= alert["confidence"] <= 1.0
        assert "evidence" in alert
        assert alert["evidence"]["scan_type"] == "VERTICAL"
        assert alert["evidence"]["target_host"] == target_ip
        assert alert["evidence"]["unique_ports_observed"] >= VERTICAL_SCAN_THRESHOLD
        assert len(alert["ports_sample"]) > 0

    def test_vertical_scan_sub_threshold_ignored(self):
        """Probing fewer than threshold unique ports does not trigger an alert."""
        engine = DetectionEngine()
        source_ip = "192.168.1.101"
        target_ip = "192.168.1.10"
        alerts = []

        for i, port in enumerate(range(1, VERTICAL_SCAN_THRESHOLD // 2 + 1)):
            packet_data = {
                "ts": 2000.0 + (i * 0.1),
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            res = engine.process_packet(packet_data)
            alerts.extend(res)

        assert len(alerts) == 0

    def test_vertical_scan_time_window_expiry(self):
        """SYN packets spread beyond PORT_SCAN_TIME_WINDOW do not trigger vertical scan alert."""
        engine = DetectionEngine()
        source_ip = "192.168.1.102"
        target_ip = "192.168.1.10"
        alerts = []

        # Send 5 packets, then jump past window, then send 5 packets
        for i in range(5):
            packet_data = {
                "ts": 3000.0 + (i * 0.5),
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": i + 1,
                "protocol": "TCP",
                "tcp_syn": True,
            }
            alerts.extend(engine.process_packet(packet_data))

        # Advance event time past window (15.0s > 10.0s window)
        for i in range(5):
            packet_data = {
                "ts": 3020.0 + (i * 0.5),
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": i + 20,
                "protocol": "TCP",
                "tcp_syn": True,
            }
            alerts.extend(engine.process_packet(packet_data))

        vertical_alerts = [a for a in alerts if a.scan_type == "VERTICAL"]
        assert len(vertical_alerts) == 0

    # =========================================================================
    # 2. HORIZONTAL PORT SCAN TESTS
    # =========================================================================

    def test_horizontal_port_scan_detection(self):
        """Probing the same destination port across >= 10 targets triggers HORIZONTAL alert."""
        engine = DetectionEngine()
        source_ip = "172.16.1.50"
        target_port = 445
        alert = None

        for i in range(1, HORIZONTAL_SCAN_THRESHOLD + 1):
            packet_data = {
                "ts": 4000.0 + (i * 0.1),
                "source_ip": source_ip,
                "destination_ip": f"10.0.0.{i}",
                "destination_port": target_port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            results = engine.process_packet(packet_data)
            for res in results:
                if res.threat_type == THREAT_TYPE_PORT_SCAN and res.scan_type == "HORIZONTAL":
                    alert = res.to_dict()

        assert alert is not None
        assert alert["threat_type"] == THREAT_TYPE_PORT_SCAN
        assert alert["scan_type"] == "HORIZONTAL"
        assert alert["severity"] in ("MEDIUM", "HIGH")
        assert alert["source_ip"] == source_ip
        assert alert["destination_port"] == target_port
        assert alert["target_count"] >= HORIZONTAL_SCAN_THRESHOLD
        assert alert["evidence"]["scan_type"] == "HORIZONTAL"
        assert alert["evidence"]["target_port"] == target_port
        assert alert["evidence"]["unique_targets_observed"] >= HORIZONTAL_SCAN_THRESHOLD
        assert len(alert["sample_targets"]) > 0

    def test_horizontal_scan_sub_threshold_ignored(self):
        """Probing fewer targets than HORIZONTAL_SCAN_THRESHOLD does not trigger an alert."""
        engine = DetectionEngine()
        alerts = []

        for i in range(1, HORIZONTAL_SCAN_THRESHOLD // 2 + 1):
            packet_data = {
                "ts": 5000.0 + (i * 0.1),
                "source_ip": "172.16.1.51",
                "destination_ip": f"10.0.0.{i}",
                "destination_port": 80,
                "protocol": "TCP",
                "tcp_syn": True,
            }
            alerts.extend(engine.process_packet(packet_data))

        assert len(alerts) == 0

    # =========================================================================
    # 3. PROTOCOL & TRAFFIC FILTERING
    # =========================================================================

    def test_non_tcp_traffic_ignored_by_scan_detector(self):
        """UDP and ICMP packets are not treated as TCP SYN scans."""
        engine = DetectionEngine()
        alerts = []

        for i in range(20):
            alerts.extend(
                engine.process_packet(
                    {
                        "ts": 6000.0 + (i * 0.1),
                        "source_ip": "192.168.1.103",
                        "destination_ip": "10.0.0.1",
                        "destination_port": 1000 + i,
                        "protocol": "UDP",
                        "tcp_syn": False,
                    }
                )
            )

        scan_alerts = [a for a in alerts if a.threat_type == THREAT_TYPE_PORT_SCAN]
        assert len(scan_alerts) == 0

    def test_tcp_ack_traffic_ignored_by_scan_detector(self):
        """Established TCP connections (SYN=0, ACK=1) do not trigger port scan alerts."""
        engine = DetectionEngine()
        alerts = []

        for i in range(20):
            alerts.extend(
                engine.process_packet(
                    {
                        "ts": 7000.0 + (i * 0.1),
                        "source_ip": "192.168.1.104",
                        "destination_ip": "10.0.0.1",
                        "destination_port": 1000 + i,
                        "protocol": "TCP",
                        "tcp_syn": False,
                        "tcp_ack": True,
                    }
                )
            )

        scan_alerts = [a for a in alerts if a.threat_type == THREAT_TYPE_PORT_SCAN]
        assert len(scan_alerts) == 0

    # =========================================================================
    # 4. SCAN COOLDOWN SUPPRESSION
    # =========================================================================

    def test_scan_cooldown_suppression(self):
        """Subsequent packets within alert cooldown period are suppressed."""
        engine = DetectionEngine()
        source_ip = "192.168.1.105"
        target_ip = "192.168.1.10"
        alerts = []

        for i in range(1, VERTICAL_SCAN_THRESHOLD + 5):
            packet_data = {
                "ts": 8000.0 + (i * 0.1),
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": i,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            res = engine.process_packet(packet_data)
            alerts.extend([a for a in res if a.scan_type == "VERTICAL"])

        # Exactly 1 alert emitted when crossing threshold; subsequent are suppressed by cooldown
        assert len(alerts) == 1

    # =========================================================================
    # 5. VOLUMETRIC TRAFFIC TESTS
    # =========================================================================

    def test_packet_count_threshold_high_traffic(self):
        """Generating burst traffic exceeding floor pps triggers VOLUMETRIC alert."""
        engine = DetectionEngine(
            config={
                "VOLUMETRIC_FLOOR_PPS": 100.0,
                "VOLUMETRIC_MIN_PACKETS": 200,
                "VOLUMETRIC_WARMUP_WINDOWS": 0,
            }
        )
        source_ip = "10.10.10.1"
        target_ip = "10.10.10.2"
        alerts = []

        for i in range(250):
            packet_data = {
                "ts": 9000.0 + (i * 0.004),
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "protocol": "TCP",
                "packet_size": 64,
            }
            alerts.extend(engine.process_packet(packet_data))

        vol_alerts = [a for a in alerts if a.threat_type == THREAT_TYPE_VOLUMETRIC]
        assert len(vol_alerts) >= 1
        first_alert = vol_alerts[0].to_dict()
        assert first_alert["threat_type"] == THREAT_TYPE_VOLUMETRIC
        assert first_alert["destination_ip"] == target_ip

    def test_rate_based_high_traffic_pps(self):
        """Burst traffic exceeding packet rate threshold triggers volumetric alert."""
        engine = DetectionEngine(
            config={
                "VOLUMETRIC_FLOOR_PPS": 150.0,
                "VOLUMETRIC_MIN_PACKETS": 200,
                "VOLUMETRIC_WARMUP_WINDOWS": 0,
            }
        )
        source_ip = "10.10.10.3"
        target_ip = "10.10.10.4"
        alerts = []

        for i in range(250):
            packet_data = {
                "ts": 10000.0 + (i * 0.004),  # 250 pps
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "protocol": "UDP",
                "packet_size": 64,
            }
            alerts.extend(engine.process_packet(packet_data))

        vol_alerts = [a for a in alerts if a.threat_type == THREAT_TYPE_VOLUMETRIC]
        assert len(vol_alerts) >= 1

    def test_byte_rate_high_traffic_bps(self):
        """Large payload traffic exceeding byte rate threshold triggers volumetric alert."""
        engine = DetectionEngine(
            config={
                "VOLUMETRIC_FLOOR_BPS": 2_000_000.0,  # 2 MB/s
                "VOLUMETRIC_MIN_PACKETS": 200,
                "VOLUMETRIC_WARMUP_WINDOWS": 0,
            }
        )
        source_ip = "10.10.10.5"
        target_ip = "10.10.10.6"
        alerts = []

        for i in range(250):
            packet_data = {
                "ts": 11000.0 + (i * 0.004),
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "protocol": "TCP",
                "packet_size": 100_000,  # 100 KB * 250 in 1s = 25 MB/s
            }
            alerts.extend(engine.process_packet(packet_data))

        vol_alerts = [a for a in alerts if a.threat_type == THREAT_TYPE_VOLUMETRIC]
        assert len(vol_alerts) >= 1
        assert vol_alerts[0].evidence["byte_rate_bps"] >= 2_000_000.0

    # =========================================================================
    # 6. STATE STORE CLEANUP & BOUNDING
    # =========================================================================

    def test_state_store_ttl_expiry(self):
        """State store purges partitions older than TTL via event-time clock."""
        engine = DetectionEngine(config={"DETECTION_STATE_TTL": 10.0})
        base_time = 12000.0

        engine.process_packet(
            {
                "ts": base_time,
                "source_ip": "192.168.1.1",
                "destination_ip": "192.168.1.2",
                "destination_port": 80,
                "protocol": "TCP",
                "tcp_syn": True,
            }
        )

        engine.process_packet(
            {
                "ts": base_time + 5.0,
                "source_ip": "192.168.1.2",
                "destination_ip": "192.168.1.3",
                "destination_port": 80,
                "protocol": "TCP",
                "tcp_syn": True,
            }
        )

        v_store = engine.state_store.get_partition("vertical")
        assert v_store.size() == 2

        # Purge at t = 12012.0 (host 1 at 12000 is older than 10.0s TTL)
        engine.cleanup_expired(base_time + 12.0)
        assert v_store.size() == 1
        assert ("192.168.1.1", "192.168.1.2") not in v_store
        assert ("192.168.1.2", "192.168.1.3") in v_store

    def test_state_store_lru_bounded_capacity(self):
        """PartitionedStateStore evicts oldest entries when max_entries capacity is reached."""
        max_cap = 5
        engine = DetectionEngine(partition_caps={"vertical": max_cap})
        base_time = 13000.0

        for i in range(max_cap):
            engine.process_packet(
                {
                    "ts": base_time + i,
                    "source_ip": f"10.0.0.{i}",
                    "destination_ip": "10.0.0.100",
                    "destination_port": 80,
                    "protocol": "TCP",
                    "tcp_syn": True,
                }
            )

        v_store = engine.state_store.get_partition("vertical")
        assert v_store.size() == max_cap

        # Adding 6th entry evicts least recently used (first entry)
        engine.process_packet(
            {
                "ts": base_time + 10.0,
                "source_ip": "10.0.0.99",
                "destination_ip": "10.0.0.100",
                "destination_port": 80,
                "protocol": "TCP",
                "tcp_syn": True,
            }
        )

        assert v_store.size() == max_cap
        assert v_store.evictions == 1
        assert ("10.0.0.0", "10.0.0.100") not in v_store
        assert ("10.0.0.99", "10.0.0.100") in v_store

    # =========================================================================
    # 7. ALERT EVIDENCE SCHEMA COMPLETENESS
    # =========================================================================

    def test_alert_evidence_schema_completeness(self):
        """Verify alert evidence dictionaries provide complete forensic context."""
        engine = DetectionEngine()
        vert_alert = None

        for port in range(1, VERTICAL_SCAN_THRESHOLD + 1):
            res = engine.process_packet(
                {
                    "ts": 14000.0 + (port * 0.1),
                    "source_ip": "1.1.1.1",
                    "destination_ip": "2.2.2.2",
                    "destination_port": port,
                    "protocol": "TCP",
                    "tcp_syn": True,
                }
            )
            for a in res:
                if a.scan_type == "VERTICAL":
                    vert_alert = a.to_dict()

        assert vert_alert is not None
        assert "evidence" in vert_alert
        evidence = vert_alert["evidence"]
        assert evidence["scan_type"] == "VERTICAL"
        assert evidence["target_host"] == "2.2.2.2"
        assert evidence["unique_ports_observed"] == VERTICAL_SCAN_THRESHOLD
        assert evidence["threshold"] == VERTICAL_SCAN_THRESHOLD
        assert evidence["window_seconds"] == PORT_SCAN_TIME_WINDOW
        assert isinstance(evidence["sample_ports"], list)
