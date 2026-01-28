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
