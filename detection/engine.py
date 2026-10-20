"""
Centralized Detection Engine for SentinelX.

Owns the partitioned bounded state store, enforces monotonic event-time clock
progression (Correction 6), and orchestrates all stateful rule detectors.
Contains no wall-clock time calls or module-level mutable state.
"""

import threading
from typing import Any

from config.settings import (
    DETECTION_STATE_TTL,
    SYN_FLOOD_HALF_OPEN_TTL,
)
from detection.alert import Alert
from detection.detectors.base import BaseDetector
from detection.detectors.port_scan import HorizontalPortScanDetector, VerticalPortScanDetector
from detection.detectors.slow_scan import SlowScanDetector
from detection.detectors.syn_flood import SynFloodDetector
from detection.detectors.volumetric import VolumetricAnomalyDetector
from detection.state_store import PartitionedStateStore


class DetectionEngine:
    """
    Unified stateful intrusion detection engine.
    Processes packets strictly using event-time timestamps from packet capture headers.
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        partition_caps: dict[str, int] | None = None,
    ):
        self.config = config or {}
        self.state_store = PartitionedStateStore(partition_caps=partition_caps)
        self.clock: float = 0.0
        self._lock = threading.RLock()
        self._last_cleanup_clock: float = 0.0
        self._cleanup_interval_seconds: float = 10.0

        # Instantiate detectors
        self.detectors: list[BaseDetector] = [
            VerticalPortScanDetector(self.config, self.state_store),
            HorizontalPortScanDetector(self.config, self.state_store),
            SlowScanDetector(self.config, self.state_store),
            SynFloodDetector(self.config, self.state_store),
            VolumetricAnomalyDetector(self.config, self.state_store),
        ]

    def process_packet(self, packet_data: dict[str, Any]) -> list[Alert]:
        """
        Process a normalized packet event through all registered detectors.
        Updates monotonic event clock and handles event-time state eviction.
        """
        event_ts = packet_data.get("ts")
        with self._lock:
            if event_ts is not None:
                # Monotonic clock never regresses even on out-of-order packets (Correction 6)
                if event_ts > self.clock:
                    self.clock = event_ts

            alerts: list[Alert] = []
            for detector in self.detectors:
                detected = detector.observe(packet_data, self.clock)
                if detected:
                    alerts.extend(detected)

            # Opportunistic event-time cleanup
            if (self.clock - self._last_cleanup_clock) >= self._cleanup_interval_seconds:
                self.cleanup_expired(self.clock)
                self._last_cleanup_clock = self.clock

            return alerts

    def cleanup_expired(self, current_clock: float) -> dict[str, int]:
        """
        Evict expired entries from state partitions using the engine's event-time clock.
        """
        evicted = {}
        ttl = float(self.config.get("DETECTION_STATE_TTL", DETECTION_STATE_TTL))
        half_open_ttl = float(self.config.get("SYN_FLOOD_HALF_OPEN_TTL", SYN_FLOOD_HALF_OPEN_TTL))

        # Evict half-open connections with their dedicated TTL
        half_open_store = self.state_store.get_partition("syn_flood_half_open")
        evicted["syn_flood_half_open"] = half_open_store.evict_expired(
            current_clock - half_open_ttl,
            get_last_seen=lambda val: val if isinstance(val, (int, float)) else getattr(val, "last_seen", None),
        )

        # Evict other state partitions with general TTL
        for name in ["vertical", "horizontal", "slow_scan", "volumetric", "cooldowns"]:
            store = self.state_store.get_partition(name)
            evicted[name] = store.evict_expired(
                current_clock - ttl,
                get_last_seen=lambda val: (
                    val.get("last_seen")
                    if isinstance(val, dict)
                    else (val if isinstance(val, (int, float)) else getattr(val, "last_seen", None))
                ),
            )

        return evicted

    def reset(self) -> None:
        """Reset state store partitions and event clock."""
        with self._lock:
            self.state_store.clear()
            self.clock = 0.0
            self._last_cleanup_clock = 0.0

    def get_metrics(self) -> dict[str, Any]:
        """Return operational and memory metrics from the engine and state partitions."""
        with self._lock:
            return {
                "engine_clock": self.clock,
                "partitions": self.state_store.get_metrics(),
            }
