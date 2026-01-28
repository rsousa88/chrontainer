from __future__ import annotations

from typing import Callable

import sqlite3


class ScheduleViewRepository:
    """Repository for schedule view queries."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def list_with_host_names(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT s.id, s.container_name, s.action, s.cron_expression, s.enabled, s.last_run, h.name, s.one_time, s.run_at
                FROM schedules s
                LEFT JOIN hosts h ON s.host_id = h.id
                '''
            )
            return cursor.fetchall()
        finally:
            conn.close()
