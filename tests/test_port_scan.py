from detection.rule_engine import (
    detect_port_scan,
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
    connection_tracker.clear()
    last_scan_alert_time.clear()

    packet_data = create_syn_packet(443)

    # This packet is normal TCP ACK traffic, not a SYN scan
    packet_data["tcp_syn"] = False

    alert = detect_port_scan(packet_data)

    assert alert is None

    print("Normal TCP traffic test passed!")


def test_udp_traffic_not_detected():
    connection_tracker.clear()
    last_scan_alert_time.clear()

    packet_data = create_syn_packet(53)
    packet_data["protocol"] = "UDP"
    packet_data["tcp_syn"] = False

    alert = detect_port_scan(packet_data)

    assert alert is None

    print("UDP traffic test passed!")


def test_port_scan_cooldown():
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


if __name__ == "__main__":
    test_port_scan_detection()
    test_normal_tcp_traffic_not_detected()
    test_udp_traffic_not_detected()
    test_port_scan_cooldown()

    print("\nAll port scan tests passed!")