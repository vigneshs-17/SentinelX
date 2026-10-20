"""
Slow Scan Detector for SentinelX.

Detects low-and-slow port scans designed to evade fast-window detectors:
Threshold = 20 unique ports/hosts across a 300-second (5 minute) event-time window.
"""

from typing import Any

from config.settings import (
    SCAN_TYPE_SLOW_HORIZONTAL,
    SCAN_TYPE_SLOW_VERTICAL,
    SLOW_SCAN_ALERT_COOLDOWN,
    SLOW_SCAN_THRESHOLD,
    SLOW_SCAN_TIME_WINDOW,
    THREAT_TYPE_PORT_SCAN,
)
from detection.alert import Alert
from detection.detectors.base import BaseDetector
from detection.scoring import calculate_confidence, calculate_severity
from detection.state_store import PartitionedStateStore
from detection.utils import is_multicast_or_broadcast


class SlowScanDetector(BaseDetector):
    """
    Stateful detector for slow port scans across extended event-time windows (300s).
    Evaluates both slow vertical and slow horizontal scans.
    """

    VERSION = "SlowScanDetector v2.0"

    def __init__(self, config: dict[str, Any], state_store: PartitionedStateStore):
        super().__init__(config, state_store)
        self.store = state_store.get_partition("slow_scan")
        self.threshold = int(self.config.get("SLOW_SCAN_THRESHOLD", SLOW_SCAN_THRESHOLD))
        self.window = float(self.config.get("SLOW_SCAN_TIME_WINDOW", SLOW_SCAN_TIME_WINDOW))
        self.cooldown = float(self.config.get("SLOW_SCAN_ALERT_COOLDOWN", SLOW_SCAN_ALERT_COOLDOWN))

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

        alerts: list[Alert] = []
        cutoff = event_time - self.window

        # -----------------------------------------------------------------
        # 1. Slow Vertical Scan: (source_ip, "SLOW_V", destination_ip)
        # -----------------------------------------------------------------
        v_key = ("SLOW_V", source_ip, destination_ip)
        v_entry = self.store.get(v_key)

        if v_entry is None:
            v_ports = {destination_port: event_time}
            v_first_seen = event_time
        else:
            v_ports = {p: ts for p, ts in v_entry["ports"].items() if ts >= cutoff}
            v_first_seen = v_entry.get("first_seen", event_time)
            if destination_port in v_ports:
                v_ports[destination_port] = event_time
            elif len(v_ports) < (self.threshold + 1):
                v_ports[destination_port] = event_time

        self.store.put(
            v_key,
            {"ports": v_ports, "first_seen": v_first_seen, "last_seen": event_time},
        )

        v_port_count = len(v_ports)
        if v_port_count >= self.threshold:
            cooldown_key = ("SLOW_VERTICAL", source_ip, destination_ip)
            is_fast_active = self.is_in_cooldown(
                ("VERTICAL", source_ip, destination_ip), event_time, 60.0
            ) or self.is_in_cooldown(("VERTICAL", source_ip), event_time, 60.0)
            if not is_fast_active and not self.is_in_cooldown(cooldown_key, event_time, self.cooldown):
                self.record_cooldown(cooldown_key, event_time)
                self.record_cooldown(("SLOW_VERTICAL", source_ip), event_time)

                port_sample = sorted(list(v_ports.keys()))[:10]
                severity = calculate_severity(v_port_count, self.threshold)
                confidence = calculate_confidence(v_port_count, self.threshold)

                evidence = {
                    "scan_type": SCAN_TYPE_SLOW_VERTICAL,
                    "unique_ports_observed": v_port_count,
                    "threshold": self.threshold,
                    "window_seconds": self.window,
                    "target_host": destination_ip,
                    "sample_ports": port_sample,
                }

                alerts.append(
                    Alert(
                        threat_type=THREAT_TYPE_PORT_SCAN,
                        scan_type=SCAN_TYPE_SLOW_VERTICAL,
                        severity=severity,
                        confidence=confidence,
                        detector=self.VERSION,
                        first_seen=v_first_seen,
                        last_seen=event_time,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        protocol="TCP",
                        evidence=evidence,
                        message=(
                            f"Slow Vertical TCP port scan detected from {source_ip} "
                            f"targeting {destination_ip} ({v_port_count} ports in {self.window:.0f}s)"
                        ),
                    )
                )

        # -----------------------------------------------------------------
        # 2. Slow Horizontal Scan: (source_ip, "SLOW_H", destination_port)
        # -----------------------------------------------------------------
        h_key = ("SLOW_H", source_ip, destination_port)
        h_entry = self.store.get(h_key)

        if h_entry is None:
            h_targets = {destination_ip: event_time}
            h_first_seen = event_time
        else:
            h_targets = {ip: ts for ip, ts in h_entry["targets"].items() if ts >= cutoff}
            h_first_seen = h_entry.get("first_seen", event_time)
            if destination_ip in h_targets:
                h_targets[destination_ip] = event_time
            elif len(h_targets) < (self.threshold + 1):
                h_targets[destination_ip] = event_time

        self.store.put(
            h_key,
            {"targets": h_targets, "first_seen": h_first_seen, "last_seen": event_time},
        )

        h_target_count = len(h_targets)
        if h_target_count >= self.threshold:
            cooldown_key = ("SLOW_HORIZONTAL", source_ip, destination_port)
            is_fast_active = self.is_in_cooldown(
                ("HORIZONTAL", source_ip, destination_port), event_time, 60.0
            ) or self.is_in_cooldown(("HORIZONTAL", source_ip), event_time, 60.0)
            if not is_fast_active and not self.is_in_cooldown(cooldown_key, event_time, self.cooldown):
                self.record_cooldown(cooldown_key, event_time)
                self.record_cooldown(("SLOW_HORIZONTAL", source_ip), event_time)

                target_sample = sorted(list(h_targets.keys()))[:10]
                severity = calculate_severity(h_target_count, self.threshold)
                confidence = calculate_confidence(h_target_count, self.threshold)

                evidence = {
                    "scan_type": SCAN_TYPE_SLOW_HORIZONTAL,
                    "unique_targets_observed": h_target_count,
                    "threshold": self.threshold,
                    "window_seconds": self.window,
                    "target_port": destination_port,
                    "sample_targets": target_sample,
                }

                alerts.append(
                    Alert(
                        threat_type=THREAT_TYPE_PORT_SCAN,
                        scan_type=SCAN_TYPE_SLOW_HORIZONTAL,
                        severity=severity,
                        confidence=confidence,
                        detector=self.VERSION,
                        first_seen=h_first_seen,
                        last_seen=event_time,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        protocol="TCP",
                        evidence=evidence,
                        message=(
                            f"Slow Horizontal TCP port scan detected from {source_ip} "
                            f"targeting port {destination_port} across {h_target_count} hosts in {self.window:.0f}s"
                        ),
                    )
                )

        return alerts
