import ipaddress
import threading
import time
from collections import defaultdict, deque

from config.settings import (
    DETECTION_STATE_TTL,
    HIGH_TRAFFIC_ALERT_COOLDOWN,
    HIGH_TRAFFIC_BYTE_RATE_THRESHOLD,
    HIGH_TRAFFIC_PACKET_RATE_THRESHOLD,
    HIGH_TRAFFIC_PACKET_THRESHOLD,
    HIGH_TRAFFIC_RESET_THRESHOLD,
    HIGH_TRAFFIC_TIME_WINDOW,
    THREAT_TYPE_HIGH_TRAFFIC,
)
from detection.scoring import calculate_confidence, calculate_severity

# Concurrency lock protecting traffic history and sliding window state
_traffic_lock = threading.Lock()

# Backward-compatible tracking structures
packet_tracker: defaultdict[str, list[float]] = defaultdict(list)
alert_active: dict[str, bool] = {}

# Sliding window rate tracking using deque for O(1) pruning
_traffic_history: dict[str, deque] = defaultdict(deque)
_last_alert_time: dict[str, float] = {}


def is_multicast_or_broadcast(ip_address: str | None) -> bool:
    """
    Multicast and broadcast check using the ipaddress module.
    Ignores only 255.255.255.255, unspecified addresses (0.0.0.0, ::),
    and IPv4/IPv6 multicast (224.0.0.0/4, ff00::/8).
    Does NOT ignore host addresses like 10.0.1.255.
    """
    if not ip_address:
        return False

    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    if ip.is_multicast or ip.is_unspecified:
        return True

    if ip_address == "255.255.255.255":
        return True

    return False


def detect_high_traffic(packet_data: dict) -> dict | None:
    """
    Rate-based volumetric anomaly detection:

    Evaluates packet rate (pps) and byte rate (Bps) over a sliding time window.
    Filters out broadcast/multicast traffic and suppresses duplicate alerts.

    Returns structured alert with rate metrics, evidence, and confidence score,
    or None if traffic is within normal operating thresholds.
    """
    source_ip = packet_data.get("source_ip")
    destination_ip = packet_data.get("destination_ip")
    protocol = packet_data.get("protocol")
    packet_size = packet_data.get("packet_size", 60)

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
    cutoff = current_time - HIGH_TRAFFIC_TIME_WINDOW

    with _traffic_lock:
        # Synchronize backward-compatible packet_tracker
        tracker = packet_tracker[source_ip]
        tracker.append(current_time)
        packet_tracker[source_ip] = [ts for ts in tracker if ts >= cutoff]
        compat_packet_count = len(packet_tracker[source_ip])

        # Synchronize rate tracker deque (timestamp, byte_size)
        history = _traffic_history[source_ip]
        history.append((current_time, packet_size))

        # O(1) sliding window prune
        while history and history[0][0] < cutoff:
            history.popleft()

        packet_count = max(compat_packet_count, len(history))
        total_bytes = sum(entry[1] for entry in history)

        effective_window = max(0.1, HIGH_TRAFFIC_TIME_WINDOW)
        packet_rate = packet_count / effective_window
        byte_rate = total_bytes / effective_window

        # Reset alert state when traffic drops sufficiently (backward-compatible)
        if packet_count <= HIGH_TRAFFIC_RESET_THRESHOLD:
            alert_active[source_ip] = False

        # Check alert conditions:
        # 1. Packet count threshold reached (e.g. 1000 packets)
        # 2. Packet rate threshold reached (e.g. 200 pps) with minimum 50 packets
        # 3. Byte rate threshold reached (e.g. 2 MB/s) with minimum 50 packets
        is_anomaly = (
            packet_count >= HIGH_TRAFFIC_PACKET_THRESHOLD
            or (packet_rate >= HIGH_TRAFFIC_PACKET_RATE_THRESHOLD and packet_count >= 50)
            or (byte_rate >= HIGH_TRAFFIC_BYTE_RATE_THRESHOLD and packet_count >= 50)
        )

        if not is_anomaly:
            return None

        # Cooldown & active suppression check
        last_alert = _last_alert_time.get(source_ip)
        in_cooldown = last_alert is not None and (current_time - last_alert < HIGH_TRAFFIC_ALERT_COOLDOWN)

        if alert_active.get(source_ip, False) or in_cooldown:
            return None

        alert_active[source_ip] = True
        _last_alert_time[source_ip] = current_time

    # Payload generation outside critical section
    ratios = [packet_count / HIGH_TRAFFIC_PACKET_THRESHOLD, packet_rate / HIGH_TRAFFIC_PACKET_RATE_THRESHOLD]
    if byte_rate > 0:
        ratios.append(byte_rate / HIGH_TRAFFIC_BYTE_RATE_THRESHOLD)
    max_ratio = max(ratios)

    severity = calculate_severity(max_ratio, 1.0)
    confidence = calculate_confidence(max_ratio, 1.0)

    return {
        "threat_type": THREAT_TYPE_HIGH_TRAFFIC,
        "severity": severity,
        "confidence": confidence,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "packet_count": packet_count,
        "packet_rate": round(packet_rate, 1),
        "byte_rate": round(byte_rate, 1),
        "evidence": {
            "observation_window_seconds": HIGH_TRAFFIC_TIME_WINDOW,
            "packet_count": packet_count,
            "packet_rate_pps": round(packet_rate, 1),
            "packet_rate_threshold_pps": HIGH_TRAFFIC_PACKET_RATE_THRESHOLD,
            "byte_rate_bps": round(byte_rate, 1),
            "byte_rate_threshold_bps": HIGH_TRAFFIC_BYTE_RATE_THRESHOLD,
            "total_bytes": total_bytes,
        },
        "message": (
            f"Abnormally high traffic detected from {source_ip} "
            f"({packet_count} packets, {packet_rate:.1f} pps in {HIGH_TRAFFIC_TIME_WINDOW:.0f}s)"
        ),
    }


def cleanup_traffic_state(now: float | None = None, ttl: float = DETECTION_STATE_TTL) -> int:
    """Clean up expired traffic tracking entries to enforce bounded memory."""
    current_time = now if now is not None else time.time()
    cutoff = current_time - ttl

    with _traffic_lock:
        expired_ips = [ip for ip, history in list(_traffic_history.items()) if not history or history[-1][0] < cutoff]

        for ip in expired_ips:
            _traffic_history.pop(ip, None)
            packet_tracker.pop(ip, None)
            alert_active.pop(ip, None)
            _last_alert_time.pop(ip, None)

        return len(expired_ips)
