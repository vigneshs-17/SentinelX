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


if __name__ == "__main__":
    test_normal_traffic()
    test_multicast_traffic()
    test_non_tcp_udp_traffic()
    test_high_traffic_detection()

    print("\nAll traffic rule tests passed!")