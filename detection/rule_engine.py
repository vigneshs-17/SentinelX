from collections import defaultdict
import time

from config.settings import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW,
    PORT_SCAN_ALERT_COOLDOWN,
)


# Store scan attempts from each source IP
connection_tracker = defaultdict(list)

# Prevent repeated alerts for the same source
last_scan_alert_time = {}


def detect_port_scan(packet_data):
    source_ip = packet_data["source_ip"]
    destination_port = packet_data["destination_port"]
    protocol = packet_data["protocol"]
    tcp_syn = packet_data.get("tcp_syn", False)

    # We only detect TCP SYN scans
    if (
        source_ip is None
        or destination_port is None
        or protocol != "TCP"
        or not tcp_syn
    ):
        return None

    current_time = time.time()

    # Record this SYN attempt
    connection_tracker[source_ip].append(
        (current_time, destination_port)
    )

    # Keep only recent attempts
    connection_tracker[source_ip] = [
        entry
        for entry in connection_tracker[source_ip]
        if current_time - entry[0] <= PORT_SCAN_TIME_WINDOW
    ]

    # Get unique destination ports
    unique_ports = {
        entry[1]
        for entry in connection_tracker[source_ip]
    }

    # Check whether scan threshold has been reached
    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        previous_alert = last_scan_alert_time.get(source_ip)

        # Prevent repeated alerts during cooldown
        if (
            previous_alert is not None
            and current_time - previous_alert
            < PORT_SCAN_ALERT_COOLDOWN
        ):
            return None

        # Record alert time
        last_scan_alert_time[source_ip] = current_time

        return {
            "threat_type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": source_ip,
            "destination_port_count": len(unique_ports),
            "message": (
                f"Possible TCP SYN port scan detected "
                f"from {source_ip}"
            )
        }

    return None


if __name__ == "__main__":
    print("SentinelX Detection Engine")
    print("TCP SYN port scan detection loaded successfully.")
    print(
        f"Threshold: {PORT_SCAN_THRESHOLD} unique ports "
        f"in {PORT_SCAN_TIME_WINDOW} seconds"
    )
    print(
        f"Alert cooldown: "
        f"{PORT_SCAN_ALERT_COOLDOWN} seconds"
    )