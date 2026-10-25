"""An in-memory, per-IP token bucket that slows down credential stuffing on
the auth endpoints.

It is per worker process: with W workers on N instances a client gets up to
W x N times the budget (requests are spread over workers by the kernel). For
strict global limits use a shared store (Redis) or the edge proxy / WAF.
"""

import time
from typing import Final

# Bounds memory under a flood of distinct IPs.
MAX_TRACKED_CLIENTS: Final = 100_000
_IDLE_EVICT: Final = 600.0
_CLEANUP_EVERY: Final = 60.0


class IPRateLimiter:
    """Token bucket per client IP. Single-threaded use from the event loop
    needs no locking: ``allow`` never awaits."""

    __slots__ = ("_buckets", "_burst", "_last_cleanup", "_rate")

    def __init__(self, per_minute: int, burst: int) -> None:
        self._rate: Final = per_minute / 60.0  # tokens per second
        self._burst: Final = float(burst)
        # ip -> (tokens, last refill time)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._last_cleanup = time.monotonic()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        if now - self._last_cleanup > _CLEANUP_EVERY or len(self._buckets) >= MAX_TRACKED_CLIENTS:
            self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] <= _IDLE_EVICT}
            self._last_cleanup = now
        bucket = self._buckets.get(ip)
        if bucket is None:
            if len(self._buckets) >= MAX_TRACKED_CLIENTS:
                return False  # fail closed rather than grow without bound
            tokens = self._burst
        else:
            tokens = min(self._burst, bucket[0] + (now - bucket[1]) * self._rate)
        if tokens < 1.0:
            self._buckets[ip] = (tokens, now)
            return False
        self._buckets[ip] = (tokens - 1.0, now)
        return True

    @property
    def retry_after_seconds(self) -> int:
        return int(1 / self._rate) + 1
