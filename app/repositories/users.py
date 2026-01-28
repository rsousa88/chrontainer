from __future__ import annotations

from typing import Callable, Optional, Tuple

import sqlite3


class UserRepository:
    """Repository for users."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def get_by_id(self, user_id: int) -> Optional[Tuple[int, str, str]]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
            return cursor.fetchone()
        finally:
            conn.close()

    def get_password_hash(self, user_id: int) -> Optional[str]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            conn.close()

    def update_password(self, user_id: int, password_hash: str) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (password_hash, user_id),
            )
            conn.commit()
        finally:
            conn.close()
