from __future__ import annotations

import threading
import time


class DiskUsageService:
    """Disk usage cache + async refresh."""

    def __init__(
        self,
        *,
        logger,
        cache_ttl_seconds: int,
    ):
        self._logger = logger
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache = {}
        self._cache_lock = threading.RLock()
        self._inflight = set()
        self._inflight_lock = threading.Lock()

    def get_cached_disk_usage(self, host_id):
        with self._cache_lock:
            entry = self._cache.get(host_id)
            if not entry:
                return None
            if time.time() - entry['timestamp'] > self._cache_ttl_seconds:
                return None
            return entry['data']

    def set_cached_disk_usage(self, host_id, data):
        with self._cache_lock:
            self._cache[host_id] = {'timestamp': time.time(), 'data': data}

    def refresh_disk_usage_async(self, host_id, docker_client):
        def run():
            try:
                disk = docker_client.api.df()
                if disk:
                    self.set_cached_disk_usage(host_id, disk)
                    self._logger.info(
                        "Disk usage async cached for host %s: images=%s containers=%s volumes=%s cache=%s layers=%s",
                        host_id,
                        len(disk.get('Images', []) or []),
                        len(disk.get('Containers', []) or []),
                        len(disk.get('Volumes', []) or []),
                        len(disk.get('BuildCache', []) or []),
                        disk.get('LayersSize'),
                    )
            except Exception as error:
                self._logger.warning("Disk usage async df failed for host %s: %s", host_id, error)
            finally:
                with self._inflight_lock:
                    self._inflight.discard(host_id)

        with self._inflight_lock:
            if host_id in self._inflight:
                return
            self._inflight.add(host_id)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
