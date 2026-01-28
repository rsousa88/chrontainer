from __future__ import annotations

from typing import Callable

import sqlite3


class TagRepository:
    """Repository for tags.""""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def list_all(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, color FROM tags ORDER BY name')
            return cursor.fetchall()
        finally:
            conn.close()

    def create(self, name: str, color: str) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO tags (name, color) VALUES (?, ?)', (name, color))
            tag_id = cursor.lastrowid
            conn.commit()
            return tag_id
        finally:
            conn.close()

    def delete(self, tag_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM tags WHERE id = ?', (tag_id,))
            conn.commit()
        finally:
            conn.close()
