from __future__ import annotations

from typing import Callable

import sqlite3


class ContainerTagRepository:
    """Repository for container tag relationships."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def list_all(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT ct.container_id, ct.host_id, t.id, t.name, t.color
                FROM container_tags ct
                JOIN tags t ON ct.tag_id = t.id
                '''
            )
            return cursor.fetchall()
        finally:
            conn.close()

    def list_for_container(self, container_id: str, host_id: int):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT t.id, t.name, t.color
                FROM tags t
                JOIN container_tags ct ON t.id = ct.tag_id
                WHERE ct.container_id = ? AND ct.host_id = ?
                ORDER BY t.name
                ''',
                (container_id, host_id),
            )
            return cursor.fetchall()
        finally:
            conn.close()

    def add(self, container_id: str, host_id: int, tag_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR IGNORE INTO container_tags (container_id, host_id, tag_id) VALUES (?, ?, ?)',
                (container_id, host_id, tag_id),
            )
            conn.commit()
        finally:
            conn.close()

    def remove(self, container_id: str, host_id: int, tag_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM container_tags WHERE container_id = ? AND host_id = ? AND tag_id = ?',
                (container_id, host_id, tag_id),
            )
            conn.commit()
        finally:
            conn.close()
