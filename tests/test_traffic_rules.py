import threading

from config.settings import (
    THREAT_TYPE_VOLUMETRIC,
)
from detection.engine import DetectionEngine


def create_packet(source_ip="192.168.1.100", destination_ip="192.168.1.10", ts=1000.0, size=60):
    return {
        "ts": ts,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "packet_size": size,
    }


def test_normal_traffic():
    engine = DetectionEngine()
    packet_data = create_packet()

    alerts = []
    for i in range(100):
        pkt = dict(packet_data)
        pkt["ts"] = 1000.0 + (i * 0.1)
        res = engine.process_packet(pkt)
        if res:
            alerts.extend(res)

    assert len(alerts) == 0
    print("Normal traffic test passed!")


def test_multicast_traffic():
    engine = DetectionEngine()
    packet_data = create_packet(destination_ip="224.0.0.251")

    res = engine.process_packet(packet_data)
    assert len(res) == 0
    print("Multicast traffic test passed!")


def test_non_tcp_udp_traffic():
    engine = DetectionEngine()
    packet_data = create_packet()
    packet_data["protocol"] = "OTHER"

    res = engine.process_packet(packet_data)
    assert len(res) == 0
    print("Non-TCP/UDP traffic test passed!")


def test_high_traffic_detection():
    # Configure low floor to trigger volumetric alert deterministically in test
    engine = DetectionEngine(
        config={
            "VOLUMETRIC_FLOOR_PPS": 100.0,
            "VOLUMETRIC_MIN_PACKETS": 200,
            "VOLUMETRIC_WARMUP_WINDOWS": 0,
        }
    )

    first_alert = None
    alerts_seen = []

    for i in range(250):
        pkt = create_packet(ts=2000.0 + (i * 0.004))  # 250 pps
        res = engine.process_packet(pkt)
        for a in res:
            if a.threat_type == THREAT_TYPE_VOLUMETRIC:
                alerts_seen.append(a)
                if first_alert is None:
                    first_alert = a.to_dict()

    assert first_alert is not None
    assert first_alert["threat_type"] == THREAT_TYPE_VOLUMETRIC
    assert first_alert["severity"] in ("MEDIUM", "HIGH")
    assert first_alert["evidence"]["packet_count"] >= 200

    # Additional high-traffic packets during cooldown must be suppressed
    extra_pkt = create_packet(ts=2001.5)
    duplicate_res = engine.process_packet(extra_pkt)
    vol_dups = [a for a in duplicate_res if a.threat_type == THREAT_TYPE_VOLUMETRIC]
    assert len(vol_dups) == 0

    print("High traffic detection test passed!")
    print("Active alert suppression test passed!")


def test_high_traffic_byte_rate_detection():
    """Verify byte-rate volumetric threshold."""
    engine = DetectionEngine(
        config={
            "VOLUMETRIC_FLOOR_BPS": 1000000.0,  # 1 MB/s
            "VOLUMETRIC_MIN_PACKETS": 200,
            "VOLUMETRIC_WARMUP_WINDOWS": 0,
        }
    )

    first_alert = None
    for i in range(250):
        pkt = create_packet(ts=3000.0 + (i * 0.004), size=50000)  # 50 KB * 250 = 12.5 MB in 1s
        res = engine.process_packet(pkt)
        for a in res:
            if a.threat_type == THREAT_TYPE_VOLUMETRIC and first_alert is None:
                first_alert = a.to_dict()

    assert first_alert is not None
    assert first_alert["threat_type"] == THREAT_TYPE_VOLUMETRIC
    assert first_alert["evidence"]["byte_rate_bps"] >= 1000000.0


def test_multi_worker_concurrency_same_source_ip():
    """
    Concurrency test: two concurrent worker threads process high-rate traffic.
    Verifies thread-safe processing and reliable alert generation.
    """
    engine = DetectionEngine(
        config={
            "VOLUMETRIC_FLOOR_PPS": 100.0,
            "VOLUMETRIC_MIN_PACKETS": 200,
            "VOLUMETRIC_WARMUP_WINDOWS": 0,
        }
    )
    errors = []
    alerts = []
    barrier = threading.Barrier(2)

    def worker_loop(thread_id, count):
        barrier.wait()
        for i in range(count):
            pkt = create_packet(source_ip="192.168.100.99", ts=4000.0 + (i * 0.002))
            try:
                res = engine.process_packet(pkt)
                if res:
                    alerts.extend(res)
            except Exception as exc:
                errors.append(f"Thread-{thread_id}: {exc}")

    t1 = threading.Thread(target=worker_loop, args=(1, 300))
    t2 = threading.Thread(target=worker_loop, args=(2, 300))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(errors) == 0, f"Encountered concurrency exceptions: {errors}"
    assert len(alerts) >= 1, "Expected high traffic alert to be generated under burst"


def test_multi_worker_concurrency_multiple_source_ips():
    """
    Concurrency test across 10 distinct source IPs simultaneously.
    """
    engine = DetectionEngine()
    errors = []
    barrier = threading.Barrier(4)

    def worker_loop(thread_id):
        barrier.wait()
        for i in range(250):
            src_ip = f"10.50.0.{i % 10}"
            pkt = create_packet(source_ip=src_ip, ts=5000.0 + (i * 0.01))
            try:
                engine.process_packet(pkt)
            except Exception as exc:
                errors.append(f"Worker-{thread_id} IP-{src_ip}: {exc}")

    threads = [threading.Thread(target=worker_loop, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Encountered concurrency exceptions: {errors}"


def test_bounded_state_and_cleanup():
    """Verify that state store evicts expired entries using event-time clock."""
    engine = DetectionEngine(config={"DETECTION_STATE_TTL": 60.0})

    base_ts = 6000.0
    # Seed 20 distinct destination IPs
    for i in range(20):
        pkt = create_packet(destination_ip=f"10.99.0.{i}", ts=base_ts + i)
        engine.process_packet(pkt)

    v_store = engine.state_store.get_partition("volumetric")
    assert v_store.size() == 20

    # Advance clock by 120 seconds (beyond DETECTION_STATE_TTL=60s)
    evicted = engine.cleanup_expired(base_ts + 120.0)
    assert evicted["volumetric"] == 20
    assert v_store.size() == 0


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
