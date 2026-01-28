from __future__ import annotations

from typing import Callable, Optional

import sqlite3


class LogsRepository:
    """Repository for action logs."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def insert_action_log(
        self,
        schedule_id: Optional[int],
        container_name: str,
        action: str,
        status: str,
        message: str,
        host_id: int = 1,
    ) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO logs (schedule_id, host_id, container_name, action, status, message) VALUES (?, ?, ?, ?, ?, ?)',
                (schedule_id, host_id, container_name, action, status, message),
            )
            conn.commit()
        finally:
            conn.close()
