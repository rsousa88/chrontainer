from __future__ import annotations

import threading
import time


class ContainerStatsService:
    """Container stats caching."""

    def __init__(self, *, cache_ttl_seconds: int):
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache = {}
        self._cache_lock = threading.RLock()

    def get_cached_container_stats(self, cache_key):
        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if not entry:
                return None
            if time.time() - entry['timestamp'] > self._cache_ttl_seconds:
                return None
            return entry['data']

    def set_cached_container_stats(self, cache_key, data):
        with self._cache_lock:
            self._cache[cache_key] = {'timestamp': time.time(), 'data': data}
