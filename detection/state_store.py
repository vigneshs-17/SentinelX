"""
Bounded, partitioned, LRU and event-time TTL state store for SentinelX detection engine.

Prevents unbounded memory growth (D3) and resource-exhaustion cross-eviction attacks
by isolating tracking tables into capped, independent partitions (Correction 1).
"""

import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any


class BoundedStateStore[T]:
    """
    Thread-safe bounded key-value store with O(1) amortized LRU eviction
    and deterministic event-time TTL pruning.
    """

    def __init__(self, name: str, max_entries: int, on_evict: Callable[[Any, T], None] | None = None):
        if max_entries <= 0:
            raise ValueError(f"max_entries must be positive, got {max_entries}")
        self.name = name
        self.max_entries = max_entries
        self.on_evict = on_evict
        self._store: OrderedDict[Any, T] = OrderedDict()
        self._lock = threading.RLock()
        self.evictions = 0
        self.hits = 0
        self.misses = 0

    def get(self, key: Any, default: T | None = None) -> T | None:
        """Retrieve value for key, marking it most recently used."""
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self.hits += 1
                return self._store[key]
            self.misses += 1
            return default

    def __contains__(self, key: Any) -> bool:
        with self._lock:
            return key in self._store

    def put(self, key: Any, value: T) -> None:
        """
        Store value under key.
        If key exists, update and move to MRU.
        If key is new and store is at capacity, evict the least recently used entry (LRU).
        """
        with self._lock:
            if key in self._store:
                self._store[key] = value
                self._store.move_to_end(key)
                return

            if len(self._store) >= self.max_entries:
                evicted_key, evicted_value = self._store.popitem(last=False)
                self.evictions += 1
                if self.on_evict is not None:
                    self.on_evict(evicted_key, evicted_value)

            self._store[key] = value

    def pop(self, key: Any, default: T | None = None) -> T | None:
        """Remove and return key from store if present."""
        with self._lock:
            return self._store.pop(key, default)

    def size(self) -> int:
        """Return current number of entries."""
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        """Reset all entries and counters."""
        with self._lock:
            self._store.clear()
            self.evictions = 0
            self.hits = 0
            self.misses = 0

    def evict_expired(self, cutoff_time: float, get_last_seen: Any) -> int:
        """
        Evict entries whose last_seen timestamp is strictly less than cutoff_time.
        get_last_seen is a callable or attribute getter taking the stored entry.
        Returns the number of evicted expired entries.
        """
        with self._lock:
            expired_keys = []
            for key, val in self._store.items():
                ts = get_last_seen(val) if callable(get_last_seen) else getattr(val, "last_seen", None)
                if ts is not None and ts < cutoff_time:
                    expired_keys.append(key)

            for key in expired_keys:
                self._store.pop(key, None)

            return len(expired_keys)

    def pop_expired_front(self, cutoff_time: float, get_last_seen: Callable[[T], float]) -> list[tuple[Any, T]]:
        """
        Pop entries from the LRU end while their last_seen is strictly below cutoff_time, stopping at the
        first live entry. Valid when every update goes through put() (LRU order == last-update order).
        Cost is O(expired), not O(size).
        """
        popped: list[tuple[Any, T]] = []
        with self._lock:
            while self._store:
                key = next(iter(self._store))
                if get_last_seen(self._store[key]) >= cutoff_time:
                    break
                popped.append((key, self._store.pop(key)))
        return popped

    def items_snapshot(self) -> list[tuple[Any, T]]:
        """Return entries in LRU order (oldest first) without touching recency."""
        with self._lock:
            return list(self._store.items())

    def get_metrics(self) -> dict[str, int]:
        """Return snapshot of store health metrics."""
        with self._lock:
            return {
                "size": len(self._store),
                "capacity": self.max_entries,
                "evictions": self.evictions,
                "hits": self.hits,
                "misses": self.misses,
            }


class PartitionedStateStore:
    """
    Manages isolated BoundedStateStore partitions for each detector and subsystem.

    This ensures that high churn in one detector (e.g., half-open connections
    or spoofed random sources) cannot evict another detector's state (e.g., SYN-flood aggregates
    or cooldown tracking).
    """

    def __init__(self, partition_caps: dict[str, int] | None = None):
        from config.settings import (
            PARTITION_CAP_COOLDOWNS,
            PARTITION_CAP_HORIZONTAL,
            PARTITION_CAP_SCAN_ATTEMPTS,
            PARTITION_CAP_SCAN_COMPLETED,
            PARTITION_CAP_SLOW_SCAN,
            PARTITION_CAP_SYN_FLOOD_AGGREGATES,
            PARTITION_CAP_SYN_FLOOD_HALF_OPEN,
            PARTITION_CAP_VERTICAL,
            PARTITION_CAP_VOLUMETRIC,
        )

        default_caps = {
            "vertical": PARTITION_CAP_VERTICAL,
            "horizontal": PARTITION_CAP_HORIZONTAL,
            "slow_scan": PARTITION_CAP_SLOW_SCAN,
            "syn_flood_aggregates": PARTITION_CAP_SYN_FLOOD_AGGREGATES,
            "syn_flood_half_open": PARTITION_CAP_SYN_FLOOD_HALF_OPEN,
            "volumetric": PARTITION_CAP_VOLUMETRIC,
            "cooldowns": PARTITION_CAP_COOLDOWNS,
            "scan_attempts": PARTITION_CAP_SCAN_ATTEMPTS,
            "scan_completed": PARTITION_CAP_SCAN_COMPLETED,
        }

        caps = default_caps if partition_caps is None else {**default_caps, **partition_caps}
        self.partitions: dict[str, BoundedStateStore[Any]] = {
            name: BoundedStateStore(name=name, max_entries=cap) for name, cap in caps.items()
        }
        self._lock = threading.RLock()

    def get_partition(self, name: str) -> BoundedStateStore[Any]:
        """Retrieve partition by name. Creates a default partition if not registered."""
        with self._lock:
            if name not in self.partitions:
                self.partitions[name] = BoundedStateStore(name=name, max_entries=1000)
            return self.partitions[name]

    def clear(self) -> None:
        """Clear all partitions."""
        with self._lock:
            for store in self.partitions.values():
                store.clear()

    def get_metrics(self) -> dict[str, dict[str, int]]:
        """Return metrics across all partitions."""
        with self._lock:
            return {name: store.get_metrics() for name, store in self.partitions.items()}
