from collections import defaultdict, deque
import time
from typing import Optional, Dict

from config.settings import (
    HIGH_TRAFFIC_PACKET_THRESHOLD,
    HIGH_TRAFFIC_PACKET_RATE_THRESHOLD,
    HIGH_TRAFFIC_BYTE_RATE_THRESHOLD,
    HIGH_TRAFFIC_TIME_WINDOW,
    HIGH_TRAFFIC_RESET_THRESHOLD,
    HIGH_TRAFFIC_ALERT_COOLDOWN,
    THREAT_TYPE_HIGH_TRAFFIC,
    DETECTION_STATE_TTL,
)


# Backward-compatible tracking structures
packet_tracker = defaultdict(list)
alert_active = {}

# Sliding window rate tracking using deque for O(1) pruning
_traffic_history: Dict[str, deque] = defaultdict(deque)
_last_alert_time: Dict[str, float] = {}


def is_multicast_or_broadcast(ip_address: Optional[str]) -> bool:
    """
    High-performance multicast and broadcast check using fast prefix/suffix
    checks with IP address fallback.
    """
    if not ip_address:
        return False

    # Fast string-based checks
    if ip_address == "255.255.255.255" or ip_address.endswith(".255"):
        return True

    # Check IPv4 multicast range: 224.0.0.0 through 239.255.255.255
    first_octet_str = ip_address.split(".")[0] if "." in ip_address else ""
    if first_octet_str.isdigit():
        first_octet = int(first_octet_str)
        if 224 <= first_octet <= 239:
            return True

    return False


def _calculate_traffic_confidence(observed_rate: float, threshold_rate: float) -> float:
    """Calculate transparent confidence score based on rate excess."""
    if threshold_rate <= 0:
        return 0.80
    ratio = observed_rate / threshold_rate
    score = 0.80 + min(0.18, max(0.0, (ratio - 1.0) * 0.10))
    return round(score, 2)


def detect_high_traffic(packet_data: dict) -> Optional[dict]:
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

    # Synchronize backward-compatible packet_tracker
    packet_tracker[source_ip].append(current_time)
    cutoff = current_time - HIGH_TRAFFIC_TIME_WINDOW
    packet_tracker[source_ip] = [
        ts for ts in packet_tracker[source_ip]
        if ts >= cutoff
    ]
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

    if is_anomaly:
        # Cooldown & active suppression check
        last_alert = _last_alert_time.get(source_ip)
        in_cooldown = (
            last_alert is not None
            and (current_time - last_alert < HIGH_TRAFFIC_ALERT_COOLDOWN)
        )

        if alert_active.get(source_ip, False) or in_cooldown:
            return None

        alert_active[source_ip] = True
        _last_alert_time[source_ip] = current_time

        confidence = _calculate_traffic_confidence(
            max(packet_rate, packet_count / HIGH_TRAFFIC_TIME_WINDOW),
            HIGH_TRAFFIC_PACKET_RATE_THRESHOLD,
        )

        return {
            "threat_type": THREAT_TYPE_HIGH_TRAFFIC,
            "severity": "HIGH",
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

    return None


def cleanup_traffic_state(now: Optional[float] = None, ttl: float = DETECTION_STATE_TTL) -> int:
    """Clean up expired traffic tracking entries to enforce bounded memory."""
    current_time = now if now is not None else time.time()
    cutoff = current_time - ttl

    expired_ips = [
        ip for ip, history in list(_traffic_history.items())
        if not history or history[-1][0] < cutoff
    ]

    for ip in expired_ips:
        del _traffic_history[ip]
        if ip in packet_tracker:
            del packet_tracker[ip]
        if ip in alert_active:
            del alert_active[ip]
        if ip in _last_alert_time:
            del _last_alert_time[ip]

    return len(expired_ips)