"""
In-memory token-bucket rate limiting (one bucket per identity: user, API key, or client IP).

Bounded memory: buckets live in an LRU store capped at RATE_LIMIT_MAX_BUCKETS, so a flood of distinct source
addresses cannot grow it without limit (the oldest idle buckets are evicted and simply start full again).
State is per process; run one API process, or accept per-process budgets.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from config.settings import RATE_LIMIT_MAX_BUCKETS
from detection.state_store import BoundedStateStore


def monotonic() -> float:
    """Seam so tests can pin time."""
    return time.monotonic()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int  # until the bucket is full again
    retry_after: int  # seconds until one request is allowed (0 when allowed)


class _Bucket:
    __slots__ = ("stamp", "tokens")

    def __init__(self, tokens: float, stamp: float) -> None:
        self.tokens = tokens
        self.stamp = stamp


class RateLimiter:
    def __init__(self, max_buckets: int = RATE_LIMIT_MAX_BUCKETS) -> None:
        self._buckets: BoundedStateStore[_Bucket] = BoundedStateStore("ratelimit", max_buckets)
        self._lock = threading.Lock()

    def check(self, key: str, per_minute: int) -> Decision:
        """Take one token from key's bucket (capacity = per_minute, refill = per_minute / 60 per second)."""
        now = monotonic()
        rate = per_minute / 60.0
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(float(per_minute), now)
            else:
                bucket.tokens = min(float(per_minute), bucket.tokens + (now - bucket.stamp) * rate)
                bucket.stamp = now
            allowed = bucket.tokens >= 1.0
            if allowed:
                bucket.tokens -= 1.0
            self._buckets.put(key, bucket)
            retry = 0 if allowed else math.ceil((1.0 - bucket.tokens) / rate)
            reset = math.ceil((per_minute - bucket.tokens) / rate)
            return Decision(allowed, per_minute, int(bucket.tokens), reset, retry)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def size(self) -> int:
        return self._buckets.size()


limiter = RateLimiter()
