from __future__ import annotations

from typing import Callable

import sqlite3


class HostMetricsRepository:
    """Repository for host metrics queries."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def list_enabled_hosts(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name FROM hosts WHERE enabled = 1')
            return cursor.fetchall()
        finally:
            conn.close()

    def get_metrics(self, docker_client):
        info = docker_client.info()
        total_mem = info.get('MemTotal', 0) or 0
        total_mem_gb = round(total_mem / (1024**3), 2) if total_mem else 0
        return {
            'os': info.get('OperatingSystem', 'Unknown'),
            'docker_version': info.get('ServerVersion', 'Unknown'),
            'cpus': info.get('NCPU', 0),
            'total_memory_gb': total_mem_gb,
            'containers_running': info.get('ContainersRunning', 0),
            'containers_stopped': info.get('ContainersStopped', 0),
            'containers_paused': info.get('ContainersPaused', 0),
        }
