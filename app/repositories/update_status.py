from __future__ import annotations

from typing import Callable, Optional

import sqlite3


class UpdateStatusRepository:
    """Repository for container update status cache."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def upsert(
        self,
        container_id: str,
        host_id: int,
        has_update: bool,
        remote_digest: Optional[str],
        error: Optional[str],
        note: Optional[str],
        checked_at: Optional[str],
    ) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT OR REPLACE INTO update_status (
                    container_id, host_id, has_update, remote_digest, error, note, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    container_id,
                    host_id,
                    1 if has_update else 0,
                    remote_digest,
                    error,
                    note,
                    checked_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def list_all(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT container_id, host_id, has_update, remote_digest, error, note, checked_at
                FROM update_status
                '''
            )
            return cursor.fetchall()
        finally:
            conn.close()
