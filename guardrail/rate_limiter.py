"""Per-user token bucket (in-memory). Use Redis for multi-process deployments."""
from __future__ import annotations

import threading
import time
from typing import Dict, Tuple


class RateLimiter:
    def __init__(self, capacity: float = 10, refill_per_sec: float = 0.5, clock=time.monotonic):
        self.capacity, self.refill, self.clock = capacity, refill_per_sec, clock
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            ok = tokens >= cost
            self._buckets[key] = (tokens - cost if ok else tokens, now)
            return ok
