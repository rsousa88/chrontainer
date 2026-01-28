from __future__ import annotations

from typing import Callable

import sqlite3


class AppLogRepository:
    """Repository for application logs (logs table)."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def list_recent(self, limit: int = 100):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,))
            return cursor.fetchall()
        finally:
            conn.close()
