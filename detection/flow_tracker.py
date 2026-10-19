"""
Legacy compatibility module for flow tracker.
Contains no wall-clock time calls or mutable module-level state.
"""

from typing import Any


class HostActivity:
    """Empty host activity placeholder for backwards compatibility."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass


class FlowTracker:
    """Empty flow tracker placeholder for backwards compatibility."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def clear(self) -> None:
        pass

    def record_packet(self, *args: Any, **kwargs: Any) -> None:
        pass

    def get_vertical_scan_ports(self, *args: Any, **kwargs: Any) -> set[int]:
        return set()

    def get_horizontal_scan_targets(self, *args: Any, **kwargs: Any) -> set[str]:
        return set()

    def get_traffic_rate(self, *args: Any, **kwargs: Any) -> tuple[int, float, int, float, float]:
        return 0, 0.0, 0, 0.0, 10.0

    def cleanup_expired(self, *args: Any, **kwargs: Any) -> int:
        return 0

    def evict_lru(self, *args: Any, **kwargs: Any) -> int:
        return 0


flow_tracker = FlowTracker()
