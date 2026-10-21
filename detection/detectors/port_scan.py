"""
Stateful, event-time Vertical and Horizontal TCP SYN Port Scan Detectors.

Enforces bounded per-target tracking dictionaries (capped at threshold + 1)
and O(1) LRU eviction via partitioned BoundedStateStore.
"""

from typing import Any

from config.settings import (
    HORIZONTAL_SCAN_THRESHOLD,
    PORT_SCAN_ALERT_COOLDOWN,
    PORT_SCAN_TIME_WINDOW,
    SCAN_TYPE_HORIZONTAL,
    SCAN_TYPE_VERTICAL,
    THREAT_TYPE_PORT_SCAN,
    VERTICAL_SCAN_THRESHOLD,
)
from detection.alert import Alert
from detection.detectors.base import BaseDetector
from detection.handshakes import HandshakeTracker
from detection.scoring import calculate_confidence, calculate_severity
from detection.state_store import PartitionedStateStore
from detection.utils import is_multicast_or_broadcast


class VerticalPortScanDetector(BaseDetector):
    """
    Detects vertical port scans: single source probing many ports on a single target.
    Keyed by (source_ip, destination_ip).
    """

    VERSION = "VerticalPortScanDetector v2.0"

    def __init__(self, config: dict[str, Any], state_store: PartitionedStateStore):
        super().__init__(config, state_store)
        self.store = state_store.get_partition("vertical")
        self.handshakes = HandshakeTracker(state_store)
        self.threshold = int(self.config.get("VERTICAL_SCAN_THRESHOLD", VERTICAL_SCAN_THRESHOLD))
        self.window = float(self.config.get("PORT_SCAN_TIME_WINDOW", PORT_SCAN_TIME_WINDOW))
        self.cooldown = float(self.config.get("PORT_SCAN_ALERT_COOLDOWN", PORT_SCAN_ALERT_COOLDOWN))

    def observe(self, event: dict[str, Any], engine_clock: float) -> list[Alert]:
        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")
        protocol = event.get("protocol")
        tcp_syn = event.get("tcp_syn", False)
        event_time = event.get("ts", engine_clock)

        if not source_ip or not destination_ip or destination_port is None:
            return []
        if protocol != "TCP" or not tcp_syn:
            return []
        if is_multicast_or_broadcast(destination_ip):
            return []

        key = (source_ip, destination_ip)
        # Entry format: {"ports": dict[int, float], "first_seen": float, "last_seen": float}
        entry = self.store.get(key)
        cutoff = event_time - self.window

        if entry is None:
            ports: dict[int, float] = {destination_port: event_time}
            first_seen = event_time
        else:
            # Ports whose handshake completed are normal connections, not probes.
            ports = {
                p: ts
                for p, ts in entry["ports"].items()
                if ts >= cutoff and not self.handshakes.completed(source_ip, destination_ip, p, ts)
            }
            first_seen = entry.get("first_seen", event_time)
            if destination_port in ports:
                ports[destination_port] = event_time
            elif len(ports) < (self.threshold + 1):
                ports[destination_port] = event_time

        new_entry = {
            "ports": ports,
            "first_seen": first_seen,
            "last_seen": event_time,
        }
        self.store.put(key, new_entry)

        unique_port_count = len(ports)
        if unique_port_count >= self.threshold:
            cooldown_key = ("VERTICAL", source_ip, destination_ip)
            if not self.is_in_cooldown(cooldown_key, event_time, self.cooldown):
                self.record_cooldown(cooldown_key, event_time)
                # Also cooldown source-wide to avoid duplicate floods
                self.record_cooldown(("VERTICAL", source_ip), event_time)

                port_sample = sorted(list(ports.keys()))[:10]
                severity = calculate_severity(unique_port_count, self.threshold)
                confidence = calculate_confidence(unique_port_count, self.threshold)

                evidence = {
                    "scan_type": SCAN_TYPE_VERTICAL,
                    "unique_ports_observed": unique_port_count,
                    "threshold": self.threshold,
                    "window_seconds": self.window,
                    "target_host": destination_ip,
                    "sample_ports": port_sample,
                }

                alert = Alert(
                    threat_type=THREAT_TYPE_PORT_SCAN,
                    scan_type=SCAN_TYPE_VERTICAL,
                    severity=severity,
                    confidence=confidence,
                    detector=self.VERSION,
                    first_seen=first_seen,
                    last_seen=event_time,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    protocol="TCP",
                    evidence=evidence,
                    message=(
                        f"Vertical TCP SYN port scan detected from {source_ip} "
                        f"targeting {destination_ip} ({unique_port_count} unique ports in {self.window:.0f}s)"
                    ),
                )
                return [alert]

        return []


class HorizontalPortScanDetector(BaseDetector):
    """
    Detects horizontal port scans: single source probing the same destination port across many hosts.
    Keyed by (source_ip, destination_port).
    """

    VERSION = "HorizontalPortScanDetector v2.0"

    def __init__(self, config: dict[str, Any], state_store: PartitionedStateStore):
        super().__init__(config, state_store)
        self.store = state_store.get_partition("horizontal")
        self.handshakes = HandshakeTracker(state_store)
        self.threshold = int(self.config.get("HORIZONTAL_SCAN_THRESHOLD", HORIZONTAL_SCAN_THRESHOLD))
        self.window = float(self.config.get("PORT_SCAN_TIME_WINDOW", PORT_SCAN_TIME_WINDOW))
        self.cooldown = float(self.config.get("PORT_SCAN_ALERT_COOLDOWN", PORT_SCAN_ALERT_COOLDOWN))

    def observe(self, event: dict[str, Any], engine_clock: float) -> list[Alert]:
        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")
        protocol = event.get("protocol")
        tcp_syn = event.get("tcp_syn", False)
        event_time = event.get("ts", engine_clock)

        if not source_ip or not destination_ip or destination_port is None:
            return []
        if protocol != "TCP" or not tcp_syn:
            return []
        if is_multicast_or_broadcast(destination_ip):
            return []

        key = (source_ip, destination_port)
        entry = self.store.get(key)
        cutoff = event_time - self.window

        if entry is None:
            targets: dict[str, float] = {destination_ip: event_time}
            first_seen = event_time
        else:
            # Hosts whose handshake completed are normal connections (browsing), not probes.
            targets = {
                ip: ts
                for ip, ts in entry["targets"].items()
                if ts >= cutoff and not self.handshakes.completed(source_ip, ip, destination_port, ts)
            }
            first_seen = entry.get("first_seen", event_time)
            if destination_ip in targets:
                targets[destination_ip] = event_time
            elif len(targets) < (self.threshold + 1):
                targets[destination_ip] = event_time

        new_entry = {
            "targets": targets,
            "first_seen": first_seen,
            "last_seen": event_time,
        }
        self.store.put(key, new_entry)

        target_count = len(targets)
        if target_count >= self.threshold:
            cooldown_key = ("HORIZONTAL", source_ip, destination_port)
            if not self.is_in_cooldown(cooldown_key, event_time, self.cooldown):
                self.record_cooldown(cooldown_key, event_time)
                self.record_cooldown(("HORIZONTAL", source_ip), event_time)

                target_sample = sorted(list(targets.keys()))[:10]
                severity = calculate_severity(target_count, self.threshold)
                confidence = calculate_confidence(target_count, self.threshold)

                evidence = {
                    "scan_type": SCAN_TYPE_HORIZONTAL,
                    "unique_targets_observed": target_count,
                    "threshold": self.threshold,
                    "window_seconds": self.window,
                    "target_port": destination_port,
                    "sample_targets": target_sample,
                }

                alert = Alert(
                    threat_type=THREAT_TYPE_PORT_SCAN,
                    scan_type=SCAN_TYPE_HORIZONTAL,
                    severity=severity,
                    confidence=confidence,
                    detector=self.VERSION,
                    first_seen=first_seen,
                    last_seen=event_time,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    protocol="TCP",
                    evidence=evidence,
                    message=(
                        f"Horizontal TCP SYN port scan detected from {source_ip} "
                        f"targeting port {destination_port} across {target_count} hosts in {self.window:.0f}s"
                    ),
                )
                return [alert]

        return []
