from capture.packet_parser import parse_packet
from detection.rule_engine import (
    detect_port_scan,
    connection_tracker,
    last_scan_alert_time,
)
from logs.alert_logger import log_alert


def create_syn_packet(port):
    from scapy.all import IP, TCP

    return (
        IP(
            src="192.168.1.100",
            dst="192.168.1.10"
        )
        / TCP(
            sport=50000,
            dport=port,
            flags="S"
        )
    )


def test_full_detection_pipeline():
    connection_tracker.clear()
    last_scan_alert_time.clear()

    source_ip = "192.168.1.100"

    alert = None

    # Simulate a TCP SYN scan against 10 ports
    for port in range(20, 30):

        packet = create_syn_packet(port)

        packet_data = parse_packet(packet)

        result = detect_port_scan(packet_data)

        if result is not None:
            alert = result

    # Detection engine should detect the scan
    assert alert is not None
    assert alert["threat_type"] == "PORT_SCAN"
    assert alert["severity"] == "HIGH"
    assert alert["source_ip"] == source_ip

    # Send the alert through the logger
    saved_alert = log_alert(alert)

    # Verify the alert was saved
    assert saved_alert["threat_type"] == "PORT_SCAN"
    assert saved_alert["severity"] == "HIGH"
    assert saved_alert["source_ip"] == source_ip
    assert "timestamp" in saved_alert

    print("Packet parser test passed!")
    print("Detection engine test passed!")
    print("Alert logger test passed!")
    print("Full detection pipeline test passed!")


if __name__ == "__main__":
    import os
    import tempfile
    from database.database import initialize_database
    with tempfile.TemporaryDirectory() as temp_dir:
        os.environ["SENTINELX_DB_PATH"] = os.path.join(temp_dir, "test.db")
        os.environ["SENTINELX_ALERT_LOG"] = os.path.join(temp_dir, "test.json")
        initialize_database()
        test_full_detection_pipeline()