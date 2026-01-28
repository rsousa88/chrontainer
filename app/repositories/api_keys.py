from __future__ import annotations

from typing import Callable, Optional, Tuple

import sqlite3


class ApiKeyRepository:
    """Repository for API keys."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def get_auth_record(self, key_hash: str) -> Optional[Tuple[int, int, str, str, str]]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT ak.id, ak.user_id, ak.permissions, ak.expires_at, u.role
                FROM api_keys ak
                JOIN users u ON ak.user_id = u.id
                WHERE ak.key_hash = ?
                ''',
                (key_hash,),
            )
            return cursor.fetchone()
        finally:
            conn.close()

    def touch_last_used(self, key_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?', (key_id,))
            conn.commit()
        finally:
            conn.close()

    def list_for_user(self, user_id: int):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, name, key_prefix, permissions, created_at, last_used, expires_at FROM api_keys WHERE user_id = ?',
                (user_id,),
            )
            return cursor.fetchall()
        finally:
            conn.close()

    def create(
        self,
        user_id: int,
        name: str,
        key_hash: str,
        key_prefix: str,
        permissions: str,
        expires_at: Optional[str],
    ) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO api_keys (user_id, name, key_hash, key_prefix, permissions, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (user_id, name, key_hash, key_prefix, permissions, expires_at),
            )
            key_id = cursor.lastrowid
            conn.commit()
            return key_id
        finally:
            conn.close()

    def get_user_id(self, key_id: int) -> Optional[int]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT user_id FROM api_keys WHERE id = ?', (key_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        finally:
            conn.close()

    def get_for_user(self, key_id: int, user_id: int):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, user_id, key_prefix FROM api_keys WHERE id = ? AND user_id = ?',
                (key_id, user_id),
            )
            return cursor.fetchone()
        finally:
            conn.close()

    def delete(self, key_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
            conn.commit()
        finally:
            conn.close()

    def delete_for_user(self, key_id: int, user_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?', (key_id, user_id))
            conn.commit()
        finally:
            conn.close()
