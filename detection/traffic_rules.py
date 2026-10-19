"""
Legacy compatibility module for volumetric traffic detection.
New code should instantiate and use detection.engine.DetectionEngine.
Contains no wall-clock time calls or mutable module-level state.
"""

from typing import Any

from config.settings import (
    THREAT_TYPE_HIGH_TRAFFIC,
    THREAT_TYPE_VOLUMETRIC,
)
from detection.engine import DetectionEngine
from detection.utils import is_multicast_or_broadcast

__all__ = [
    "packet_tracker",
    "alert_active",
    "_traffic_history",
    "_last_alert_time",
    "detect_high_traffic",
    "cleanup_traffic_state",
    "is_multicast_or_broadcast",
]


class _LegacyTracker:
    """Empty state placeholder for backward compatibility with legacy test clear() hooks."""

    def clear(self) -> None:
        pass


packet_tracker = _LegacyTracker()
alert_active = _LegacyTracker()
_traffic_history = _LegacyTracker()
_last_alert_time = _LegacyTracker()


def detect_high_traffic(packet_data: dict[str, Any], engine: DetectionEngine | None = None) -> dict[str, Any] | None:
    """
    Backward-compatible volumetric anomaly detection helper.
    Delegates to the provided or temporary DetectionEngine instance.
    """
    active_engine = engine or DetectionEngine()
    alerts = active_engine.process_packet(packet_data)
    for alert in alerts:
        if alert.threat_type in (THREAT_TYPE_VOLUMETRIC, THREAT_TYPE_HIGH_TRAFFIC):
            return alert.to_dict()
    return None


def cleanup_traffic_state(*args: Any, **kwargs: Any) -> int:
    """Legacy cleanup no-op."""
    return 0
