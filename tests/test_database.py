from database.database import (
    initialize_database,
    insert_alert,
    get_connection
)


def test_database():
    # Make sure the database and alerts table exist
    initialize_database()

    test_alert = {
        "timestamp": "2026-09-06T20:00:00",
        "threat_type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "message": "Test port scan alert"
    }

    # Insert test alert
    insert_alert(test_alert)

    # Verify that the alert was stored
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT threat_type, severity, source_ip
        FROM alerts
        ORDER BY id DESC
        LIMIT 1
    """)

    result = cursor.fetchone()
    connection.close()

    assert result is not None
    assert result[0] == "PORT_SCAN"
    assert result[1] == "HIGH"
    assert result[2] == "192.168.1.100"

    print("Database test passed!")


if __name__ == "__main__":
    test_database()