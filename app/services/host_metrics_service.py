from __future__ import annotations

import threading
import time


class HostMetricsService:
    """Host metrics caching and retrieval."""

    def __init__(
        self,
        *,
        host_metrics_repo,
        docker_manager,
        cache_ttl_seconds: int,
    ):
        self._host_metrics_repo = host_metrics_repo
        self._docker_manager = docker_manager
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache = {}
        self._cache_lock = threading.RLock()

    def get_cached_host_metrics(self, host_id):
        with self._cache_lock:
            entry = self._cache.get(host_id)
            if not entry:
                return None
            if time.time() - entry['timestamp'] > self._cache_ttl_seconds:
                return None
            return entry['data']

    def set_cached_host_metrics(self, host_id, data):
        with self._cache_lock:
            self._cache[host_id] = {'timestamp': time.time(), 'data': data}

    def fetch_host_metrics(self, host_id):
        cached = self.get_cached_host_metrics(host_id)
        if cached:
            return cached

        docker_client = self._docker_manager.get_client(host_id)
        if not docker_client:
            raise RuntimeError("Cannot connect to Docker host")

        stats = self._host_metrics_repo.get_metrics(docker_client)
        self.set_cached_host_metrics(host_id, stats)
        return stats
