from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

import sqlite3


class SettingsRepository:
    """Repository for application settings."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def get(self, key: str) -> Optional[str]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            conn.close()

    def set(self, key: str, value: str) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)',
                (key, value, datetime.now())
            )
            conn.commit()
        finally:
            conn.close()
