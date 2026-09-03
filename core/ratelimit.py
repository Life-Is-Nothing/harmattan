"""Simple in-memory sliding-window rate limiter."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from core.config import RATE_LIMIT_PER_MIN


class RateLimiter:
    def __init__(self, max_per_minute: int = RATE_LIMIT_PER_MIN):
        self.max = max(1, int(max_per_minute))
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = time.time()
        window = 60.0
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= self.max:
                retry = max(1, int(window - (now - q[0])) + 1)
                return False, retry
            q.append(now)
            return True, 0


limiter = RateLimiter()
