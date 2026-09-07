from logs.alert_logger import log_alert, ALERT_FILE


def test_alert_logging():
    # Test alert
    test_alert = {
        "threat_type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "destination_port_count": 10,
        "message": "Test port scan alert"
    }

    # Save the alert
    saved_alert = log_alert(test_alert)

    # Verify the timestamp was added
    assert "timestamp" in saved_alert

    # Verify the alert data
    assert saved_alert["threat_type"] == "PORT_SCAN"
    assert saved_alert["severity"] == "HIGH"
    assert saved_alert["source_ip"] == "192.168.1.100"

    # Verify the JSON file exists
    assert ALERT_FILE.exists()

    print("Alert logging test passed!")


if __name__ == "__main__":
    test_alert_logging()