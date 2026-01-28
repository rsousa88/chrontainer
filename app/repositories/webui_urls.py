from __future__ import annotations

from typing import Callable, Optional

import sqlite3


class WebuiUrlRepository:
    """Repository for container web UI URLs."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def list_all(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT container_id, host_id, url FROM container_webui_urls')
            return cursor.fetchall()
        finally:
            conn.close()

    def get(self, container_id: str, host_id: int) -> Optional[str]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT url FROM container_webui_urls WHERE container_id = ? AND host_id = ?',
                (container_id, host_id),
            )
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            conn.close()

    def upsert(self, container_id: str, host_id: int, url: str) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO container_webui_urls (container_id, host_id, url, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(container_id, host_id)
                DO UPDATE SET url = excluded.url, updated_at = CURRENT_TIMESTAMP
                ''',
                (container_id, host_id, url),
            )
            conn.commit()
        finally:
            conn.close()

    def delete(self, container_id: str, host_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM container_webui_urls WHERE container_id = ? AND host_id = ?', (container_id, host_id))
            conn.commit()
        finally:
            conn.close()
