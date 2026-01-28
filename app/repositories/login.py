from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional, Tuple

import sqlite3


class LoginRepository:
    """Repository for login-related queries."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def get_user_for_login(self, username: str) -> Optional[Tuple[int, str, str, str]]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password_hash, role FROM users WHERE username = ?', (username,))
            return cursor.fetchone()
        finally:
            conn.close()

    def update_last_login(self, user_id: int, timestamp: datetime) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (timestamp, user_id))
            conn.commit()
        finally:
            conn.close()
