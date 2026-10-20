"""
Base class and interfaces for SentinelX detectors.
"""

from abc import ABC, abstractmethod
from typing import Any

from detection.alert import Alert
from detection.state_store import BoundedStateStore, PartitionedStateStore


class BaseDetector(ABC):
    """
    Abstract base class for stateful, bounded event-time detectors.
    All state is stored within partitioned BoundedStateStore instances.
    Detectors MUST NOT reference wall-clock time or declare module-level mutable state.
    """

    def __init__(self, config: dict[str, Any], state_store: PartitionedStateStore):
        self.config = config
        self.state_store = state_store
        self.cooldown_store: BoundedStateStore[float] = state_store.get_partition("cooldowns")

    @abstractmethod
    def observe(self, event: dict[str, Any], engine_clock: float) -> list[Alert]:
        """
        Process a normalized packet event using event-time engine_clock.
        Returns a list of Alert instances (empty if no threat detected).
        """
        pass

    def is_in_cooldown(self, key: Any, event_time: float, cooldown_seconds: float) -> bool:
        """Check if alert key is currently suppressed by cooldown window."""
        last_alert = self.cooldown_store.get(key)
        if last_alert is not None and (event_time - last_alert) < cooldown_seconds:
            return True
        return False

    def record_cooldown(self, key: Any, event_time: float) -> None:
        """Record alert emission event timestamp in cooldown partition."""
        self.cooldown_store.put(key, event_time)
