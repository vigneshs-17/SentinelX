import time
import pytest
from pathlib import Path
import tempfile
import os

from config.settings import (
    VERTICAL_SCAN_THRESHOLD,
    HORIZONTAL_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW,
    PORT_SCAN_ALERT_COOLDOWN,
    HIGH_TRAFFIC_PACKET_THRESHOLD,
    HIGH_TRAFFIC_PACKET_RATE_THRESHOLD,
    HIGH_TRAFFIC_BYTE_RATE_THRESHOLD,
    HIGH_TRAFFIC_TIME_WINDOW,
    HIGH_TRAFFIC_ALERT_COOLDOWN,
    DETECTION_STATE_TTL,
    MAX_TRACKED_ENTRIES,
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_HIGH_TRAFFIC,
)
from detection.flow_tracker import FlowTracker, HostActivity
from detection.rule_engine import (
    detect_port_scan,
    flow_tracker,
    connection_tracker,
    last_scan_alert_time,
)
from detection.traffic_rules import (
    detect_high_traffic,
    is_multicast_or_broadcast,
    cleanup_traffic_state,
    packet_tracker,
    alert_active,
    _traffic_history,
    _last_alert_time,
)


@pytest.fixture(autouse=True)
def reset_detection_state():
    """Reset all detection state before and after each test."""
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()
    packet_tracker.clear()
    alert_active.clear()
    _traffic_history.clear()
    _last_alert_time.clear()
    yield
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()
    packet_tracker.clear()
    alert_active.clear()
    _traffic_history.clear()
    _last_alert_time.clear()


class TestDetectionEngine:
    """Comprehensive test suite for Phase 3 Detection Engine Overhaul."""

    # =========================================================================
    # 1. VERTICAL PORT SCAN TESTS
    # =========================================================================

    def test_vertical_port_scan_detection(self):
        """Probing >= 10 unique ports on a single host triggers a VERTICAL PORT_SCAN alert."""
        source_ip = "192.168.1.100"
        target_ip = "192.168.1.10"
        alert = None

        for port in range(1, VERTICAL_SCAN_THRESHOLD + 1):
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            alert = detect_port_scan(packet_data)

        assert alert is not None
        assert alert["threat_type"] == THREAT_TYPE_PORT_SCAN
        assert alert["scan_type"] == "VERTICAL"
        assert alert["severity"] == "HIGH"
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
        source_ip = "192.168.1.101"
        target_ip = "192.168.1.10"
        alerts = []

        for port in range(1, VERTICAL_SCAN_THRESHOLD):  # threshold - 1
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            res = detect_port_scan(packet_data)
            if res is not None:
                alerts.append(res)

        assert len(alerts) == 0

    # =========================================================================
    # 2. HORIZONTAL PORT SCAN TESTS
    # =========================================================================

    def test_horizontal_port_scan_detection(self):
        """Probing 1 port across >= 10 target hosts triggers a HORIZONTAL PORT_SCAN alert."""
        source_ip = "192.168.1.200"
        sweep_port = 445
        alert = None

        for host_idx in range(1, HORIZONTAL_SCAN_THRESHOLD + 1):
            target_ip = f"10.0.0.{host_idx}"
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": sweep_port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            alert = detect_port_scan(packet_data)

        assert alert is not None
        assert alert["threat_type"] == THREAT_TYPE_PORT_SCAN
        assert alert["scan_type"] == "HORIZONTAL"
        assert alert["severity"] == "HIGH"
        assert alert["source_ip"] == source_ip
        assert alert["destination_port"] == sweep_port
        assert alert["target_count"] >= HORIZONTAL_SCAN_THRESHOLD
        assert 0.70 <= alert["confidence"] <= 1.0
        assert "evidence" in alert
        assert alert["evidence"]["scan_type"] == "HORIZONTAL"
        assert alert["evidence"]["target_port"] == sweep_port
        assert alert["evidence"]["unique_targets_observed"] >= HORIZONTAL_SCAN_THRESHOLD
        assert len(alert["sample_targets"]) > 0

    def test_horizontal_scan_sub_threshold_ignored(self):
        """Probing fewer than threshold target hosts on 1 port does not trigger an alert."""
        source_ip = "192.168.1.201"
        sweep_port = 22
        alerts = []

        for host_idx in range(1, HORIZONTAL_SCAN_THRESHOLD):  # threshold - 1
            target_ip = f"10.0.0.{host_idx}"
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": sweep_port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            res = detect_port_scan(packet_data)
            if res is not None:
                alerts.append(res)

        assert len(alerts) == 0

    # =========================================================================
    # 3. SCAN FALSE POSITIVE SUPPRESSION & PROTOCOL FILTERING
    # =========================================================================

    def test_normal_tcp_non_syn_not_detected_as_scan(self):
        """Established non-SYN TCP traffic (e.g. ACK, PSH-ACK) must not trigger scan alerts."""
        source_ip = "192.168.1.50"
        target_ip = "192.168.1.10"
        alerts = []

        for port in range(1, 20):
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "tcp_syn": False,  # Established session, not SYN probe
                "packet_size": 512,
            }
            res = detect_port_scan(packet_data)
            if res is not None:
                alerts.append(res)

        assert len(alerts) == 0

    def test_udp_traffic_not_detected_by_port_scan(self):
        """UDP traffic must not trigger TCP SYN port scan alerts."""
        source_ip = "192.168.1.60"
        target_ip = "192.168.1.10"
        alerts = []

        for port in range(1, 20):
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "UDP",
                "tcp_syn": False,
                "packet_size": 128,
            }
            res = detect_port_scan(packet_data)
            if res is not None:
                alerts.append(res)

        assert len(alerts) == 0

    def test_scan_cooldown_suppression(self):
        """Repeated scan packets within cooldown window must not flood alerts."""
        source_ip = "192.168.1.70"
        target_ip = "192.168.1.10"
        alerts = []

        for port in range(1, 25):
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            res = detect_port_scan(packet_data)
            if res is not None:
                alerts.append(res)

        # Only the packet that crossed the threshold triggers an alert; subsequent are suppressed by cooldown
        assert len(alerts) == 1

    # =========================================================================
    # 4. VOLUMETRIC TRAFFIC DETECTION TESTS
    # =========================================================================

    def test_packet_count_threshold_high_traffic(self):
        """Generating packets >= HIGH_TRAFFIC_PACKET_THRESHOLD triggers HIGH_TRAFFIC alert."""
        source_ip = "10.10.10.1"
        target_ip = "10.10.10.2"
        alert = None

        for _ in range(HIGH_TRAFFIC_PACKET_THRESHOLD):
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "protocol": "TCP",
                "packet_size": 64,
            }
            alert = detect_high_traffic(packet_data)

        assert alert is not None
        assert alert["threat_type"] == THREAT_TYPE_HIGH_TRAFFIC
        assert alert["severity"] == "HIGH"
        assert alert["source_ip"] == source_ip
        assert alert["destination_ip"] == target_ip
        assert alert["packet_count"] >= HIGH_TRAFFIC_PACKET_THRESHOLD
        assert 0.70 <= alert["confidence"] <= 1.0
        assert "evidence" in alert
        assert "packet_rate_pps" in alert["evidence"]

    def test_rate_based_high_traffic_pps(self):
        """Burst traffic exceeding HIGH_TRAFFIC_PACKET_RATE_THRESHOLD triggers rate-based alert."""
        source_ip = "10.10.10.3"
        target_ip = "10.10.10.4"
        alert = None

        # Over HIGH_TRAFFIC_TIME_WINDOW (5.0s), 200.0 pps requires >= 1000 packets
        num_packets = int(HIGH_TRAFFIC_PACKET_RATE_THRESHOLD * HIGH_TRAFFIC_TIME_WINDOW) + 10

        for _ in range(num_packets):
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "protocol": "UDP",
                "packet_size": 64,
            }
            res = detect_high_traffic(packet_data)
            if res is not None:
                alert = res

        assert alert is not None
        assert alert["threat_type"] == THREAT_TYPE_HIGH_TRAFFIC
        assert alert["packet_rate"] >= HIGH_TRAFFIC_PACKET_RATE_THRESHOLD
        assert alert["evidence"]["packet_rate_pps"] >= HIGH_TRAFFIC_PACKET_RATE_THRESHOLD

    def test_byte_rate_high_traffic_bps(self):
        """Large payload traffic exceeding HIGH_TRAFFIC_BYTE_RATE_THRESHOLD triggers alert."""
        source_ip = "10.10.10.5"
        target_ip = "10.10.10.6"
        alert = None

        # 100 packets of 110,000 bytes = 11,000,000 bytes in 5s window -> 2,200,000 Bps > 2,000,000 Bps threshold
        packet_size = 110000
        for _ in range(100):
            packet_data = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "protocol": "TCP",
                "packet_size": packet_size,
            }
            res = detect_high_traffic(packet_data)
            if res is not None:
                alert = res

        assert alert is not None
        assert alert["threat_type"] == THREAT_TYPE_HIGH_TRAFFIC
        assert alert["byte_rate"] >= HIGH_TRAFFIC_BYTE_RATE_THRESHOLD
        assert alert["evidence"]["byte_rate_bps"] >= HIGH_TRAFFIC_BYTE_RATE_THRESHOLD

    def test_multicast_and_broadcast_filtering(self):
        """Multicast and broadcast traffic must be silently filtered without alerts."""
        multicast_destinations = [
            "224.0.0.1",        # All hosts multicast
            "224.0.0.251",      # mDNS
            "239.255.255.250",  # SSDP
            "255.255.255.255",  # Limited broadcast
            "192.168.1.255",    # Subnet directed broadcast
        ]

        for mcast_ip in multicast_destinations:
            assert is_multicast_or_broadcast(mcast_ip) is True

            # Generate heavy packet flood to multicast address
            alerts = []
            for _ in range(HIGH_TRAFFIC_PACKET_THRESHOLD + 50):
                packet_data = {
                    "source_ip": "192.168.1.99",
                    "destination_ip": mcast_ip,
                    "protocol": "UDP",
                    "packet_size": 256,
                }
                res = detect_high_traffic(packet_data)
                if res is not None:
                    alerts.append(res)

            assert len(alerts) == 0, f"Expected zero alerts for broadcast/multicast IP: {mcast_ip}"

    # =========================================================================
    # 5. FLOW TRACKER, BOUNDED MEMORY & TTL EVICTION TESTS
    # =========================================================================

    def test_flow_tracker_ttl_expiry(self):
        """FlowTracker purges host entries older than TTL."""
        tracker = FlowTracker(ttl=10.0, max_entries=100)
        base_time = 1000.0

        # Add host 1 at t=1000
        tracker.record_packet(
            source_ip="192.168.1.1",
            destination_ip="192.168.1.2",
            destination_port=80,
            protocol="TCP",
            tcp_syn=True,
            current_time=base_time,
        )

        # Add host 2 at t=1005
        tracker.record_packet(
            source_ip="192.168.1.2",
            destination_ip="192.168.1.3",
            destination_port=80,
            protocol="TCP",
            tcp_syn=True,
            current_time=base_time + 5.0,
        )

        assert len(tracker.hosts) == 2

        # Advance to t=1012 (host 1 is 12s old > 10s ttl; host 2 is 7s old < 10s ttl)
        evicted = tracker.cleanup_expired(current_time=base_time + 12.0)
        assert evicted == 1
        assert "192.168.1.1" not in tracker.hosts
        assert "192.168.1.2" in tracker.hosts

    def test_flow_tracker_lru_bounded_capacity(self):
        """FlowTracker evicts oldest entries when max_entries capacity is reached."""
        max_cap = 5
        tracker = FlowTracker(ttl=60.0, max_entries=max_cap)
        base_time = 2000.0

        for i in range(max_cap):
            tracker.record_packet(
                source_ip=f"10.0.0.{i}",
                destination_ip="10.0.0.100",
                destination_port=80,
                protocol="TCP",
                current_time=base_time + i,
            )

        assert len(tracker.hosts) == max_cap

        # Adding 6th entry forces eviction of oldest
        tracker.record_packet(
            source_ip="10.0.0.99",
            destination_ip="10.0.0.100",
            destination_port=80,
            protocol="TCP",
            current_time=base_time + max_cap,
        )

        # Total hosts must never exceed max_cap
        assert len(tracker.hosts) <= max_cap
        # The oldest entry (10.0.0.0) should have been evicted
        assert "10.0.0.0" not in tracker.hosts
        assert "10.0.0.99" in tracker.hosts

    def test_traffic_rules_state_cleanup(self):
        """cleanup_traffic_state purges stale IP entries from traffic_rules."""
        source_ip = "172.16.0.10"
        packet_data = {
            "source_ip": source_ip,
            "destination_ip": "172.16.0.1",
            "protocol": "TCP",
            "packet_size": 100,
        }
        detect_high_traffic(packet_data)
        assert source_ip in _traffic_history

        # Simulate advance beyond TTL
        future_time = time.time() + DETECTION_STATE_TTL + 10.0
        purged = cleanup_traffic_state(now=future_time, ttl=DETECTION_STATE_TTL)
        assert purged >= 1
        assert source_ip not in _traffic_history
        assert source_ip not in packet_tracker

    # =========================================================================
    # 6. EVIDENCE AND CONFIDENCE METRIC INTEGRITY
    # =========================================================================

    def test_alert_evidence_schema_completeness(self):
        """Verify alert evidence dictionaries provide complete forensic context."""
        # Vertical scan
        vert_alert = None
        for port in range(1, VERTICAL_SCAN_THRESHOLD + 1):
            vert_alert = detect_port_scan({
                "source_ip": "1.1.1.1",
                "destination_ip": "2.2.2.2",
                "destination_port": port,
                "protocol": "TCP",
                "tcp_syn": True,
            })

        assert vert_alert is not None
        ev = vert_alert["evidence"]
        assert ev["scan_type"] == "VERTICAL"
        assert ev["unique_ports_observed"] == VERTICAL_SCAN_THRESHOLD
        assert ev["threshold"] == VERTICAL_SCAN_THRESHOLD
        assert ev["window_seconds"] == PORT_SCAN_TIME_WINDOW
        assert ev["target_host"] == "2.2.2.2"
        assert isinstance(ev["sample_ports"], list)
        assert 0.70 <= vert_alert["confidence"] <= 0.99


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="sentinelx_standalone_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        os.environ["SENTINELX_DB_PATH"] = str(tmp_path / "standalone.db")
        os.environ["SENTINELX_ALERT_LOG"] = str(tmp_path / "standalone_alerts.json")
        from database.database import initialize_database
        initialize_database()

        pytest.main(["-v", __file__])
