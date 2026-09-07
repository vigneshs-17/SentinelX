from collections import defaultdict
import ipaddress
import time

from config.settings import (
    HIGH_TRAFFIC_PACKET_THRESHOLD,
    HIGH_TRAFFIC_TIME_WINDOW,
    HIGH_TRAFFIC_RESET_THRESHOLD,
)


packet_tracker = defaultdict(list)
alert_active = {}


def is_multicast_or_broadcast(ip_address):
    if ip_address is None:
        return False

    try:
        ip = ipaddress.ip_address(ip_address)

        if ip.is_multicast:
            return True

        if ip_address == "255.255.255.255":
            return True

    except ValueError:
        return False

    return False


def detect_high_traffic(packet_data):

    source_ip = packet_data.get("source_ip")
    destination_ip = packet_data.get("destination_ip")
    protocol = packet_data.get("protocol")

    # Ignore incomplete packets
    if source_ip is None or destination_ip is None:
        return None

    # Only monitor TCP and UDP traffic
    if protocol not in ("TCP", "UDP"):
        return None

    # Ignore multicast and broadcast traffic
    if is_multicast_or_broadcast(destination_ip):
        return None

    current_time = time.time()

    # Add current packet timestamp
    packet_tracker[source_ip].append(current_time)

    # Remove packets outside the detection window
    packet_tracker[source_ip] = [
        timestamp
        for timestamp in packet_tracker[source_ip]
        if current_time - timestamp <= HIGH_TRAFFIC_TIME_WINDOW
    ]

    packet_count = len(packet_tracker[source_ip])

    # Reset alert state when traffic drops sufficiently
    if packet_count <= HIGH_TRAFFIC_RESET_THRESHOLD:
        alert_active[source_ip] = False

    # Detect unusually high traffic
    if packet_count >= HIGH_TRAFFIC_PACKET_THRESHOLD:

        # Prevent duplicate alerts during the same event
        if alert_active.get(source_ip, False):
            return None

        alert_active[source_ip] = True

        return {
            "threat_type": "HIGH_TRAFFIC",
            "severity": "HIGH",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "packet_count": packet_count,
            "message": (
                f"Abnormally high traffic detected "
                f"from {source_ip}"
            )
        }

    return None