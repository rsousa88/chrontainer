from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional, Tuple

import sqlite3


class HostRepository:
    """Repository for host persistence.""""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def get_by_id(self, host_id: int) -> Optional[Tuple[int, str, str, int]]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, url, enabled FROM hosts WHERE id = ?', (host_id,))
            return cursor.fetchone()
        finally:
            conn.close()

    def list_enabled(self) -> list[Tuple[int, str, str]]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, url FROM hosts WHERE enabled = 1')
            return cursor.fetchall()
        finally:
            conn.close()

    def update_last_seen(self, host_id: int, last_seen: datetime) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE hosts SET last_seen = ? WHERE id = ?', (last_seen, host_id))
            conn.commit()
        finally:
            conn.close()
