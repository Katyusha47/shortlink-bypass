"""Lightweight in-memory rate limiter using sliding-window counter."""

from __future__ import annotations
import time
from collections import defaultdict
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException, status
from app.config import settings


class SlidingWindowRateLimiter:
    """Thread-safe and async-compatible in-memory sliding-window rate limiter."""

    def __init__(
        self,
        requests_per_minute: int = settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
        window_seconds: int = 60,
    ):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self.hits: Dict[str, List[float]] = defaultdict(list)
        self.last_cleanup = time.time()

    def _cleanup_stale_entries(self, now: float) -> None:
        """Evict IP buckets that haven't had requests in window_seconds * 2."""
        if now - self.last_cleanup < 60:
            return
        self.last_cleanup = now
        stale_threshold = now - (self.window_seconds * 2)
        stale_keys = [
            ip for ip, timestamps in self.hits.items()
            if not timestamps or timestamps[-1] < stale_threshold
        ]
        for key in stale_keys:
            del self.hits[key]

    def is_allowed(self, client_ip: str) -> Tuple[bool, int, int]:
        """Check if request from client_ip is allowed under rate limits.
        
        Returns:
            (allowed: bool, remaining_requests: int, retry_after_seconds: int)
        """
        if not settings.RATE_LIMIT_ENABLED:
            return True, self.requests_per_minute, 0

        now = time.time()
        self._cleanup_stale_entries(now)

        window_start = now - self.window_seconds
        timestamps = self.hits[client_ip]

        # Filter out timestamps older than current window
        valid_timestamps = [t for t in timestamps if t > window_start]
        self.hits[client_ip] = valid_timestamps

        count = len(valid_timestamps)
        if count >= self.requests_per_minute:
            oldest = valid_timestamps[0]
            retry_after = max(1, int(oldest + self.window_seconds - now))
            return False, 0, retry_after

        # Record this hit
        self.hits[client_ip].append(now)
        remaining = max(0, self.requests_per_minute - (count + 1))
        return True, remaining, 0


rate_limiter = SlidingWindowRateLimiter()


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, taking standard proxy headers into account."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First IP in the comma-separated list is the client
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"


async def check_rate_limit(request: Request):
    """FastAPI dependency to enforce rate limits."""
    client_ip = get_client_ip(request)
    allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Rate limit exceeded. Please slow down.",
                "retry_after": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

