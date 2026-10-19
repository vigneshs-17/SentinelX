"""
Legacy compatibility module for port scan detection.
New code should instantiate and use detection.engine.DetectionEngine.
Contains no wall-clock time calls or mutable module-level state.
"""

from typing import Any

from detection.engine import DetectionEngine


class _LegacyTracker:
    """Empty state placeholder for backward compatibility with legacy test clear() hooks."""

    def clear(self) -> None:
        pass


connection_tracker = _LegacyTracker()
last_scan_alert_time = _LegacyTracker()


def detect_port_scan(packet_data: dict[str, Any], engine: DetectionEngine | None = None) -> dict[str, Any] | None:
    """
    Backward-compatible port scan detection helper.
    Delegates to the provided or temporary DetectionEngine instance.
    """
    active_engine = engine or DetectionEngine()
    alerts = active_engine.process_packet(packet_data)
    for alert in alerts:
        if alert.threat_type == "PORT_SCAN":
            return alert.to_dict()
    return None
