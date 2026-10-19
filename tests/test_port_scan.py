import threading

from detection.engine import DetectionEngine


def create_syn_packet(port: int, ts: float = 1000.0) -> dict:
    return {
        "ts": ts,
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": port,
        "packet_size": 60,
        "tcp_syn": True,
    }


def test_port_scan_detection():
    engine = DetectionEngine()
    alert = None

    # Simulate SYN attempts to 10 different ports
    for i, port in enumerate(range(20, 30)):
        packet_data = create_syn_packet(port, ts=1000.0 + (i * 0.1))
        results = engine.process_packet(packet_data)
        if results:
            alert = results[0].to_dict()

    assert alert is not None
    assert alert["threat_type"] == "PORT_SCAN"
    assert alert["severity"] in ("MEDIUM", "HIGH")
    assert alert["destination_port_count"] >= 10

    print("TCP SYN port scan detection test passed!")


def test_normal_tcp_traffic_not_detected():
    engine = DetectionEngine()
    packet_data = create_syn_packet(443, ts=1000.0)

    # This packet is normal TCP ACK traffic, not a SYN scan
    packet_data["tcp_syn"] = False
    packet_data["tcp_ack"] = True

    results = engine.process_packet(packet_data)
    assert len(results) == 0

    print("Normal TCP traffic test passed!")


def test_udp_traffic_not_detected():
    engine = DetectionEngine()
    packet_data = create_syn_packet(53, ts=1000.0)
    packet_data["protocol"] = "UDP"
    packet_data["tcp_syn"] = False

    results = engine.process_packet(packet_data)
    assert len(results) == 0

    print("UDP traffic test passed!")


def test_port_scan_cooldown():
    engine = DetectionEngine()
    alert = None

    # First scan
    for i, port in enumerate(range(20, 30)):
        results = engine.process_packet(create_syn_packet(port, ts=1000.0 + (i * 0.1)))
        if results:
            alert = results[0].to_dict()

    assert alert is not None

    # Another SYN to a new port during cooldown (at 1005.0s, cooldown is 30s)
    duplicate_results = engine.process_packet(create_syn_packet(31, ts=1005.0))
    assert len(duplicate_results) == 0

    print("Port scan cooldown test passed!")


def test_multi_worker_same_source_ip_concurrency():
    """
    Stress test multi-thread concurrency on the SAME source IP.
    Verifies thread-safety, 0 race exceptions, and reliable alert generation.
    """
    total_errors = []

    for _ in range(15):
        engine = DetectionEngine()
        barrier = threading.Barrier(2)
        iter_errors = []
        alerts = []

        def worker(worker_id, eng=engine, b=barrier, errs=iter_errors, alts=alerts):
            b.wait()
            for p in range(50):
                pkt = {
                    "ts": 1000.0 + (p * 0.01),
                    "source_ip": "192.168.1.100",
                    "destination_ip": "192.168.1.10",
                    "destination_port": 1000 + (p % 25),
                    "protocol": "TCP",
                    "tcp_syn": True,
                    "packet_size": 64,
                }
                try:
                    res = eng.process_packet(pkt)
                    if res:
                        alts.extend(res)
                except Exception as exc:
                    errs.append((type(exc).__name__, str(exc)))

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
    engine = DetectionEngine()
    errors = []
    barrier = threading.Barrier(4)

    def worker(worker_id):
        barrier.wait()
        for i in range(200):
            src_ip = f"10.0.0.{(i % 10) + 1}"
            pkt = {
                "ts": 2000.0 + (i * 0.01),
                "source_ip": src_ip,
                "destination_ip": "192.168.1.50",
                "destination_port": 1000 + (i % 20),
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            try:
                engine.process_packet(pkt)
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
    engine = DetectionEngine()
    errors = []
    alerts = []
    barrier = threading.Barrier(2)

    def worker(worker_id):
        barrier.wait()
        for h in range(15):
            pkt = {
                "ts": 3000.0 + (h * 0.1),
                "source_ip": "172.16.1.99",
                "destination_ip": f"10.10.0.{h + 1}",
                "destination_port": 445,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            try:
                res = engine.process_packet(pkt)
                if res:
                    alerts.extend(res)
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
    alert_dict = alerts[0].to_dict()
    assert alert_dict["threat_type"] == "PORT_SCAN"
    assert alert_dict["scan_type"] == "HORIZONTAL"
    assert alert_dict["destination_port"] == 445


def test_port_scan_cooldown_concurrency():
    """
    Verify that cooldown suppression is thread-safe:
    Under concurrent scan bursts from 2 workers, duplicate alerts are safely suppressed.
    """
    engine = DetectionEngine()
    alerts = []
    errors = []
    barrier = threading.Barrier(2)

    def worker(worker_id):
        barrier.wait()
        for p in range(25):
            pkt = {
                "ts": 4000.0 + (p * 0.05),
                "source_ip": "192.168.1.77",
                "destination_ip": "192.168.1.10",
                "destination_port": 2000 + p,
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            try:
                res = engine.process_packet(pkt)
                if res:
                    alerts.extend(res)
            except Exception as exc:
                errors.append((type(exc).__name__, str(exc)))

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(errors) == 0
    # Exactly 1 VERTICAL alert and 1 SLOW_VERTICAL alert emitted, subsequent suppressed by cooldown
    vertical_alerts = [a for a in alerts if a.scan_type == "VERTICAL"]
    assert len(vertical_alerts) == 1
    slow_alerts = [a for a in alerts if a.scan_type == "SLOW_VERTICAL"]
    assert len(slow_alerts) == 1


def test_state_store_cleanup_and_bounding_concurrency():
    """
    Test partitioned state store bounding and eviction under concurrent threads.
    """
    engine = DetectionEngine(partition_caps={"vertical": 20})
    errors = []
    barrier = threading.Barrier(4)

    def worker(worker_id):
        barrier.wait()
        for i in range(100):
            src_ip = f"10.0.{worker_id}.{i % 30}"
            pkt = {
                "ts": 5000.0 + (i * 0.1),
                "source_ip": src_ip,
                "destination_ip": "10.0.0.1",
                "destination_port": 80 + (i % 5),
                "protocol": "TCP",
                "tcp_syn": True,
                "packet_size": 64,
            }
            try:
                engine.process_packet(pkt)
            except Exception as exc:
                errors.append((type(exc).__name__, str(exc)))

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Observed errors: {errors}"
    v_stats = engine.state_store.get_partition("vertical").get_metrics()
    assert v_stats["size"] <= 20
