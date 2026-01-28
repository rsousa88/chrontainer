from __future__ import annotations

import sqlite3
from typing import Callable, Tuple


class StatsRepository:
    """Repository for application statistics queries."""

    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def get_active_counts(self) -> Tuple[int, int]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM schedules WHERE enabled = 1')
            active_schedules = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM hosts WHERE enabled = 1')
            active_hosts = cursor.fetchone()[0]
            return active_schedules, active_hosts
        finally:
            conn.close()
