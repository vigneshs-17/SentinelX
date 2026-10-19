from capture.packet_parser import parse_packet
from detection.engine import DetectionEngine
from logs.alert_logger import log_alert


def create_syn_packet(port: int):
    from scapy.all import IP, TCP

    return IP(src="192.168.1.100", dst="192.168.1.10") / TCP(sport=50000, dport=port, flags="S")


def test_full_detection_pipeline():
    engine = DetectionEngine()
    source_ip = "192.168.1.100"

    alert = None

    # Simulate a TCP SYN scan against 10 ports
    for port in range(20, 30):
        packet = create_syn_packet(port)
        packet_data = parse_packet(packet)
        results = engine.process_packet(packet_data)

        if results:
            alert = results[0].to_dict()

    # Detection engine should detect the scan
    assert alert is not None
    assert alert["threat_type"] == "PORT_SCAN"
    assert alert["severity"] in ("MEDIUM", "HIGH")
    assert alert["source_ip"] == source_ip

    # Send the alert through the logger
    saved_alert = log_alert(alert)

    # Verify the alert was saved
    assert saved_alert["threat_type"] == "PORT_SCAN"
    assert saved_alert["severity"] in ("MEDIUM", "HIGH")
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
