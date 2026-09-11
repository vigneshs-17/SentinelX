from collections import defaultdict
import threading
import time
from typing import Optional, Dict, Any

from config.settings import (
    PORT_SCAN_THRESHOLD,
    VERTICAL_SCAN_THRESHOLD,
    HORIZONTAL_SCAN_THRESHOLD,
    PORT_SCAN_TIME_WINDOW,
    PORT_SCAN_ALERT_COOLDOWN,
    THREAT_TYPE_PORT_SCAN,
    DETECTION_STATE_TTL,
    MAX_TRACKED_ENTRIES,
)
from detection.flow_tracker import FlowTracker


# Shared flow tracker instance with bounded capacity and TTL cleanup
flow_tracker = FlowTracker(ttl=DETECTION_STATE_TTL, max_entries=MAX_TRACKED_ENTRIES)

# Concurrency lock protecting connection tracker and port scan detection state
_scan_lock = threading.Lock()

# Backward-compatible tracking structures
connection_tracker = defaultdict(list)
last_scan_alert_time: Dict[Any, float] = {}


def _calculate_scan_confidence(count: int, threshold: int) -> float:
    """Calculate transparent confidence score based on degree of threshold exceedance."""
    if threshold <= 0 or count < threshold:
        return 0.70
    excess_ratio = (count - threshold) / max(1, threshold)
    score = 0.80 + min(0.19, excess_ratio * 0.15)
    return round(score, 2)


def detect_port_scan(packet_data: dict) -> Optional[dict]:
    """
    Enhanced port scan detection distinguishing Vertical and Horizontal scans:
    
    1. Vertical Scan: Single source probing many ports on the SAME target host.
    2. Horizontal Scan: Single source probing the SAME port across MANY target hosts.
    
    Returns structured alert with evidence, scan_type, and confidence score,
    or None if no scan pattern is met.
    """
    source_ip = packet_data.get("source_ip")
    destination_ip = packet_data.get("destination_ip") or "0.0.0.0"
    destination_port = packet_data.get("destination_port")
    protocol = packet_data.get("protocol")
    tcp_syn = packet_data.get("tcp_syn", False)

    # Only inspect TCP SYN connection attempts (fast pre-lock filter)
    if (
        source_ip is None
        or destination_port is None
        or protocol != "TCP"
        or not tcp_syn
    ):
        return None

    current_time = time.time()
    alert_info = None

    with _scan_lock:
        # Synchronize backward-compatible connection_tracker
        connection_tracker[source_ip].append((current_time, destination_port))
        cutoff = current_time - PORT_SCAN_TIME_WINDOW
        connection_tracker[source_ip] = [
            entry for entry in connection_tracker[source_ip]
            if entry[0] >= cutoff
        ]

        # Record into FlowTracker
        flow_tracker.record_packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            packet_size=packet_data.get("packet_size", 0),
            tcp_syn=True,
            current_time=current_time,
        )

        # -------------------------------------------------------------
        # 1. VERTICAL PORT SCAN DETECTION (same target, many ports)
        # -------------------------------------------------------------
        # Use destination_ip if available; fall back to aggregate for single-target tests
        target_ports = flow_tracker.get_vertical_scan_ports(
            source_ip=source_ip,
            destination_ip=destination_ip,
            window=PORT_SCAN_TIME_WINDOW,
            current_time=current_time,
        )

        # Also check aggregate ports on connection_tracker for backwards compatibility
        compat_unique_ports = {entry[1] for entry in connection_tracker[source_ip]}
        unique_port_count = max(len(target_ports), len(compat_unique_ports))

        effective_vertical_threshold = min(VERTICAL_SCAN_THRESHOLD, PORT_SCAN_THRESHOLD)

        if unique_port_count >= effective_vertical_threshold:
            cooldown_key = (source_ip, "VERTICAL", destination_ip)
            last_alert = last_scan_alert_time.get(cooldown_key) or last_scan_alert_time.get(source_ip)

            if last_alert is None or (current_time - last_alert >= PORT_SCAN_ALERT_COOLDOWN):
                last_scan_alert_time[cooldown_key] = current_time
                last_scan_alert_time[source_ip] = current_time

                port_list = sorted(list(target_ports or compat_unique_ports))[:10]
                alert_info = {
                    "scan_type": "VERTICAL",
                    "unique_port_count": unique_port_count,
                    "effective_threshold": effective_vertical_threshold,
                    "port_list": port_list,
                }

        # -------------------------------------------------------------
        # 2. HORIZONTAL PORT SCAN DETECTION (same port, many targets)
        # -------------------------------------------------------------
        if alert_info is None:
            target_hosts = flow_tracker.get_horizontal_scan_targets(
                source_ip=source_ip,
                destination_port=destination_port,
                window=PORT_SCAN_TIME_WINDOW,
                current_time=current_time,
            )

            if len(target_hosts) >= HORIZONTAL_SCAN_THRESHOLD:
                cooldown_key = (source_ip, "HORIZONTAL", destination_port)
                last_alert = last_scan_alert_time.get(cooldown_key) or last_scan_alert_time.get(source_ip)

                if last_alert is None or (current_time - last_alert >= PORT_SCAN_ALERT_COOLDOWN):
                    last_scan_alert_time[cooldown_key] = current_time
                    last_scan_alert_time[source_ip] = current_time

                    target_count = len(target_hosts)
                    target_list = sorted(list(target_hosts))[:5]
                    alert_info = {
                        "scan_type": "HORIZONTAL",
                        "target_count": target_count,
                        "target_list": target_list,
                    }

    # Payload construction outside critical section
    if alert_info is None:
        return None

    if alert_info["scan_type"] == "VERTICAL":
        unique_port_count = alert_info["unique_port_count"]
        effective_vertical_threshold = alert_info["effective_threshold"]
        port_list = alert_info["port_list"]
        confidence = _calculate_scan_confidence(unique_port_count, effective_vertical_threshold)

        return {
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "scan_type": "VERTICAL",
            "severity": "HIGH",
            "confidence": confidence,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port_count": unique_port_count,
            "ports_sample": port_list,
            "evidence": {
                "scan_type": "VERTICAL",
                "unique_ports_observed": unique_port_count,
                "threshold": effective_vertical_threshold,
                "window_seconds": PORT_SCAN_TIME_WINDOW,
                "target_host": destination_ip,
                "sample_ports": port_list,
            },
            "message": (
                f"Vertical TCP SYN port scan detected from {source_ip} "
                f"targeting {destination_ip} ({unique_port_count} unique ports in {PORT_SCAN_TIME_WINDOW:.0f}s)"
            ),
        }

    if alert_info["scan_type"] == "HORIZONTAL":
        target_count = alert_info["target_count"]
        target_list = alert_info["target_list"]
        confidence = _calculate_scan_confidence(target_count, HORIZONTAL_SCAN_THRESHOLD)

        return {
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "scan_type": "HORIZONTAL",
            "severity": "HIGH",
            "confidence": confidence,
            "source_ip": source_ip,
            "destination_port": destination_port,
            "destination_port_count": 1,
            "target_count": target_count,
            "sample_targets": target_list,
            "evidence": {
                "scan_type": "HORIZONTAL",
                "target_port": destination_port,
                "unique_targets_observed": target_count,
                "threshold": HORIZONTAL_SCAN_THRESHOLD,
                "window_seconds": PORT_SCAN_TIME_WINDOW,
                "sample_target_hosts": target_list,
            },
            "message": (
                f"Horizontal TCP SYN port scan detected from {source_ip} "
                f"targeting port {destination_port} across {target_count} hosts in {PORT_SCAN_TIME_WINDOW:.0f}s"
            ),
        }


if __name__ == "__main__":
    print("SentinelX Detection Engine")
    print("TCP SYN port scan detection loaded successfully.")
    print(f"Vertical threshold  : {VERTICAL_SCAN_THRESHOLD} unique ports per target")
    print(f"Horizontal threshold: {HORIZONTAL_SCAN_THRESHOLD} target hosts per port")
    print(f"Detection window    : {PORT_SCAN_TIME_WINDOW} seconds")
    print(f"Alert cooldown      : {PORT_SCAN_ALERT_COOLDOWN} seconds")