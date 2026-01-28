from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional, Tuple

import sqlite3


class HostRepository:
    """Repository for host persistence."""
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

    def list_all(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, url, enabled, color, last_seen, created_at FROM hosts ORDER BY id')
            return cursor.fetchall()
        finally:
            conn.close()

    def create(self, name: str, url: str, color: str, last_seen: datetime) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO hosts (name, url, enabled, color, last_seen) VALUES (?, ?, 1, ?, ?)',
                (name, url, color, last_seen),
            )
            host_id = cursor.lastrowid
            conn.commit()
            return host_id
        finally:
            conn.close()

    def update(self, host_id: int, name: str, url: str, enabled: int, color: str) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE hosts SET name = ?, url = ?, enabled = ?, color = ? WHERE id = ?',
                (name, url, enabled, color, host_id),
            )
            conn.commit()
        finally:
            conn.close()

    def delete(self, host_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
            conn.commit()
        finally:
            conn.close()

    def get_url(self, host_id: int) -> Optional[str]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT url FROM hosts WHERE id = ?', (host_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            conn.close()

    def set_enabled(self, host_id: int, enabled: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE hosts SET enabled = ? WHERE id = ?', (enabled, host_id))
            conn.commit()
        finally:
            conn.close()
