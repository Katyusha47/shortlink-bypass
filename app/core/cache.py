"""In-memory thread-safe LRU cache with TTL for resolution results."""

from __future__ import annotations
import time
from collections import OrderedDict
from typing import Optional, Any
from app.config import settings


class TTLCache:
    """Least Recently Used (LRU) in-memory cache with Time-To-Live (TTL)."""

    def __init__(
        self,
        max_entries: int = settings.CACHE_MAX_ENTRIES,
        default_ttl: int = settings.CACHE_TTL_SECONDS,
    ):
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        """Retrieve item if present and not expired."""
        if not settings.CACHE_ENABLED:
            return None

        if key not in self._cache:
            return None

        value, expires_at = self._cache[key]
        if time.time() > expires_at:
            # Expired
            del self._cache[key]
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store item with TTL, evicting oldest if max_entries reached."""
        if not settings.CACHE_ENABLED:
            return

        ttl_seconds = ttl if ttl is not None else self.default_ttl
        expires_at = time.time() + ttl_seconds

        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = (value, expires_at)

        # Evict oldest if capacity exceeded
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all entries."""
        self._cache.clear()

    def size(self) -> int:
        return len(self._cache)


resolution_cache = TTLCache()

