from detection.traffic_rules import (
    detect_high_traffic,
    packet_tracker,
    alert_active,
)


def create_packet(
    source_ip="192.168.1.100",
    destination_ip="192.168.1.10"
):
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "packet_size": 60
    }


def test_normal_traffic():
    packet_tracker.clear()
    alert_active.clear()

    packet_data = create_packet()

    alert = None

    for _ in range(100):
        alert = detect_high_traffic(packet_data)

    assert alert is None

    print("Normal traffic test passed!")


def test_multicast_traffic():
    packet_tracker.clear()
    alert_active.clear()

    packet_data = create_packet(
        destination_ip="224.0.0.251"
    )

    alert = detect_high_traffic(packet_data)

    assert alert is None

    print("Multicast traffic test passed!")


def test_non_tcp_udp_traffic():
    packet_tracker.clear()
    alert_active.clear()

    packet_data = create_packet()
    packet_data["protocol"] = "IP"

    alert = detect_high_traffic(packet_data)

    assert alert is None

    print("Non-TCP/UDP traffic test passed!")


def test_high_traffic_detection():
    packet_tracker.clear()
    alert_active.clear()

    packet_data = create_packet()

    first_alert = None

    for _ in range(1000):
        alert = detect_high_traffic(packet_data)

        if alert is not None:
            first_alert = alert

    assert first_alert is not None
    assert first_alert["threat_type"] == "HIGH_TRAFFIC"
    assert first_alert["severity"] == "HIGH"
    assert first_alert["packet_count"] >= 1000

    # Additional high-traffic packets should not create another alert
    duplicate_alert = detect_high_traffic(packet_data)

    assert duplicate_alert is None

    print("High traffic detection test passed!")
    print("Active alert suppression test passed!")


def test_high_traffic_byte_rate_detection():
    """Verify byte-rate volumetric threshold: 50 packets of 250KB exceed 2MB/s threshold."""
    packet_tracker.clear()
    alert_active.clear()

    src = "192.168.1.222"
    pkt = create_packet(source_ip=src)
    pkt["packet_size"] = 250000  # 250 KB

    first_alert = None
    for _ in range(50):
        alert = detect_high_traffic(pkt)
        if alert is not None and first_alert is None:
            first_alert = alert

    assert first_alert is not None
    assert first_alert["threat_type"] == "HIGH_TRAFFIC"
    assert first_alert["evidence"]["byte_rate_bps"] >= 2000000.0
    assert first_alert["packet_count"] == 50


def test_multi_worker_concurrency_same_source_ip():
    """
    Concurrency test simulating SENTINELX_WORKERS=2:
    Two concurrent worker threads process high-rate traffic from the SAME source IP.
    Verifies that _traffic_history is synchronized and zero 'deque mutated during iteration' occurs.
    """
    import threading
    packet_tracker.clear()
    alert_active.clear()

    src = "192.168.100.99"
    pkt = create_packet(source_ip=src)
    errors = []
    alerts = []

    def worker_loop(thread_id, count):
        for _ in range(count):
            try:
                a = detect_high_traffic(pkt)
                if a is not None:
                    alerts.append(a)
            except Exception as exc:
                errors.append(f"Thread-{thread_id}: {exc}")

    # Launch 2 concurrent threads generating 1,000 packets each
    t1 = threading.Thread(target=worker_loop, args=(1, 1000))
    t2 = threading.Thread(target=worker_loop, args=(2, 1000))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(errors) == 0, f"Encountered concurrency exceptions: {errors}"
    assert len(alerts) >= 1, "Expected high traffic alert to be generated under burst"


def test_multi_worker_concurrency_multiple_source_ips():
    """
    Concurrency test simulating 4 concurrent worker threads processing traffic
    across 10 distinct source IPs simultaneously.
    """
    import threading
    packet_tracker.clear()
    alert_active.clear()

    errors = []

    def worker_loop(thread_id):
        for i in range(250):
            src_ip = f"10.50.0.{i % 10}"
            pkt = create_packet(source_ip=src_ip)
            try:
                detect_high_traffic(pkt)
            except Exception as exc:
                errors.append(f"Worker-{thread_id} IP-{src_ip}: {exc}")

    threads = [threading.Thread(target=worker_loop, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Encountered concurrency exceptions: {errors}"


def test_bounded_state_and_cleanup():
    """Verify that cleanup_traffic_state purges stale tracking entries to prevent unbounded memory growth."""
    import time
    from detection.traffic_rules import cleanup_traffic_state, _traffic_history

    packet_tracker.clear()
    alert_active.clear()
    _traffic_history.clear()

    now = time.time()
    # Seed 20 distinct IPs
    for i in range(20):
        pkt = create_packet(source_ip=f"10.99.0.{i}")
        detect_high_traffic(pkt)

    assert len(_traffic_history) == 20

    # Advance time by 120 seconds (beyond DETECTION_STATE_TTL=60s)
    purged = cleanup_traffic_state(now=now + 120.0, ttl=60.0)
    assert purged == 20
    assert len(_traffic_history) == 0


if __name__ == "__main__":
    test_normal_traffic()
    test_multicast_traffic()
    test_non_tcp_udp_traffic()
    test_high_traffic_detection()
    test_high_traffic_byte_rate_detection()
    test_multi_worker_concurrency_same_source_ip()
    test_multi_worker_concurrency_multiple_source_ips()
    test_bounded_state_and_cleanup()

    print("\nAll traffic rule tests passed!")