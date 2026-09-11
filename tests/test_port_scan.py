import threading
import time

from detection.flow_tracker import FlowTracker
from detection.rule_engine import (
    detect_port_scan,
    flow_tracker,
    connection_tracker,
    last_scan_alert_time,
)


def create_syn_packet(port):
    return {
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": port,
        "packet_size": 60,
        "tcp_syn": True
    }


def test_port_scan_detection():
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()

    alert = None

    # Simulate SYN attempts to 10 different ports
    for port in range(20, 30):
        packet_data = create_syn_packet(port)
        result = detect_port_scan(packet_data)

        if result is not None:
            alert = result

    assert alert is not None
    assert alert["threat_type"] == "PORT_SCAN"
    assert alert["severity"] == "HIGH"
    assert alert["destination_port_count"] >= 10

    print("TCP SYN port scan detection test passed!")


def test_normal_tcp_traffic_not_detected():
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()

    packet_data = create_syn_packet(443)

    # This packet is normal TCP ACK traffic, not a SYN scan
    packet_data["tcp_syn"] = False

    alert = detect_port_scan(packet_data)

    assert alert is None

    print("Normal TCP traffic test passed!")


def test_udp_traffic_not_detected():
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()

    packet_data = create_syn_packet(53)
    packet_data["protocol"] = "UDP"
    packet_data["tcp_syn"] = False

    alert = detect_port_scan(packet_data)

    assert alert is None

    print("UDP traffic test passed!")


def test_port_scan_cooldown():
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()

    alert = None

    # First scan
    for port in range(20, 30):
        result = detect_port_scan(create_syn_packet(port))

        if result is not None:
            alert = result

    assert alert is not None

    # Another SYN to a new port during cooldown
    duplicate_alert = detect_port_scan(
        create_syn_packet(31)
    )

    assert duplicate_alert is None

    print("Port scan cooldown test passed!")


def test_multi_worker_same_source_ip_concurrency():
    """
    Stress test multi-worker concurrency on the SAME source IP.
    Executes 25 iterations of 2 concurrent worker threads sending bursts of SYN packets.
    Verifies 0 RuntimeError / deque mutation exceptions and reliable alert generation.
    """
    total_errors = []

    for _ in range(25):
        flow_tracker.clear()
        connection_tracker.clear()
        last_scan_alert_time.clear()

        barrier = threading.Barrier(2)
        iter_errors = []
        alerts = []

        def worker(worker_id):
            barrier.wait()
            for p in range(50):
                pkt = {
                    "source_ip": "192.168.1.100",
                    "destination_ip": "192.168.1.10",
                    "destination_port": 1000 + (p % 25),
                    "protocol": "TCP",
                    "tcp_syn": True,
                    "packet_size": 64,
                }
                try:
                    res = detect_port_scan(pkt)
                    if res:
                        alerts.append(res)
                except Exception as exc:
                    iter_errors.append((type(exc).__name__, str(exc)))

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        total_errors.extend(iter_errors)
        assert len(alerts) >= 1, "Expected at least 1 port scan alert generated"

    assert len(total_errors) == 0, f"Observed errors: {total_errors}"


def test_multi_worker_multiple_source_ips_concurrency():
    """
    Test 4 concurrent worker threads across 10 distinct source IPs generating concurrent bursts.
    Asserts zero race errors across threads.
    """
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()

    errors = []
    barrier = threading.Barrier(4)

    def worker(worker_id):
        barrier.wait()
        for i in range(200):
            src_ip = f"10.0.0.{(i % 10) + 1}"
            pkt = {
                "source_ip": src_ip,
                "destination_ip": "192.168.1.50",
                "destination_port": 1000 + (i % 20),
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            try:
                detect_port_scan(pkt)
            except Exception as exc:
                errors.append((type(exc).__name__, str(exc)))

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Observed errors: {errors}"


def test_horizontal_scan_detection_concurrency():
    """
    Verify Horizontal scan detection under concurrent worker execution.
    Two workers probe the same destination port across 15 distinct destination IPs.
    """
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()

    errors = []
    alerts = []
    barrier = threading.Barrier(2)

    def worker(worker_id):
        barrier.wait()
        for h in range(15):
            pkt = {
                "source_ip": "172.16.1.99",
                "destination_ip": f"10.10.0.{h + 1}",
                "destination_port": 445,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            try:
                res = detect_port_scan(pkt)
                if res:
                    alerts.append(res)
            except Exception as exc:
                errors.append((type(exc).__name__, str(exc)))

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(errors) == 0, f"Observed errors: {errors}"
    assert len(alerts) >= 1
    assert alerts[0]["threat_type"] == "PORT_SCAN"
    assert alerts[0]["scan_type"] == "HORIZONTAL"
    assert alerts[0]["destination_port"] == 445


def test_port_scan_cooldown_concurrency():
    """
    Verify that cooldown suppression is thread-safe:
    Under concurrent scan bursts from 2 workers, duplicate alerts are safely suppressed.
    """
    flow_tracker.clear()
    connection_tracker.clear()
    last_scan_alert_time.clear()

    alerts = []
    errors = []
    barrier = threading.Barrier(2)

    def worker(worker_id):
        barrier.wait()
        for p in range(25):
            pkt = {
                "source_ip": "192.168.1.77",
                "destination_ip": "192.168.1.10",
                "destination_port": 2000 + p,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            try:
                res = detect_port_scan(pkt)
                if res:
                    alerts.append(res)
            except Exception as exc:
                errors.append((type(exc).__name__, str(exc)))

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(errors) == 0
    # Exactly 1 alert emitted when crossing threshold; all subsequent suppressed by cooldown
    assert len(alerts) == 1
    assert alerts[0]["threat_type"] == "PORT_SCAN"
    assert alerts[0]["scan_type"] == "VERTICAL"


def test_flow_tracker_cleanup_and_bounding_concurrency():
    """
    Test FlowTracker state bounding, LRU eviction, and cleanup_expired under concurrent threads.
    """
    tracker = FlowTracker(ttl=5.0, max_entries=20)
    errors = []
    barrier = threading.Barrier(4)

    def worker(worker_id):
        barrier.wait()
        for i in range(100):
            src_ip = f"10.0.{worker_id}.{i % 30}"
            try:
                tracker.record_packet(
                    source_ip=src_ip,
                    destination_ip="10.0.0.1",
                    destination_port=80,
                    protocol="TCP",
                    tcp_syn=True,
                    packet_size=64,
                )
                if i % 20 == 0:
                    tracker.cleanup_expired()
                    tracker.get_vertical_scan_ports(src_ip, "10.0.0.1", window=5.0)
                    tracker.get_horizontal_scan_targets(src_ip, 80, window=5.0)
            except Exception as exc:
                errors.append((type(exc).__name__, str(exc)))

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Observed errors: {errors}"
    assert len(tracker.hosts) <= 20