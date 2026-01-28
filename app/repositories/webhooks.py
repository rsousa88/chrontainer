from __future__ import annotations

from typing import Callable, Optional, Tuple

import sqlite3


class WebhookRepository:
    """Repository for webhooks."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def get_by_token(self, token: str) -> Optional[Tuple[int, str, Optional[str], Optional[int], str, int, int]]:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, container_id, host_id, action, enabled, locked
                FROM webhooks WHERE token = ?
                """
                (token,),
            )
            return cursor.fetchone()
        finally:
            conn.close()

    def record_trigger(self, webhook_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE webhooks
                SET last_triggered = CURRENT_TIMESTAMP, trigger_count = trigger_count + 1
                WHERE id = ?
                """
                (webhook_id,),
            )
            conn.commit()
        finally:
            conn.close()

    def list_all(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT w.id, w.name, w.token, w.container_id, w.host_id, w.action,
                       w.enabled, w.locked, w.last_triggered, w.trigger_count, w.created_at, h.name
                FROM webhooks w
                LEFT JOIN hosts h ON w.host_id = h.id
                ORDER BY w.created_at DESC
                """
            )
            return cursor.fetchall()
        finally:
            conn.close()

    def create(
        self,
        name: str,
        token: str,
        container_id: Optional[str],
        host_id: Optional[int],
        action: str,
        locked: int,
    ) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO webhooks (name, token, container_id, host_id, action, locked)
                VALUES (?, ?, ?, ?, ?, ?)
                """
                (name, token, container_id, host_id, action, locked),
            )
            webhook_id = cursor.lastrowid
            conn.commit()
            return webhook_id
        finally:
            conn.close()

    def delete(self, webhook_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,))
            conn.commit()
        finally:
            conn.close()

    def toggle_enabled(self, webhook_id: int) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE webhooks SET enabled = NOT enabled WHERE id = ?', (webhook_id,))
            cursor.execute('SELECT enabled FROM webhooks WHERE id = ?', (webhook_id,))
            enabled = cursor.fetchone()[0]
            conn.commit()
            return enabled
        finally:
            conn.close()

    def toggle_locked(self, webhook_id: int) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE webhooks SET locked = NOT locked WHERE id = ?', (webhook_id,))
            cursor.execute('SELECT locked FROM webhooks WHERE id = ?', (webhook_id,))
            locked = cursor.fetchone()[0]
            conn.commit()
            return locked
        finally:
            conn.close()

    def update_token(self, webhook_id: int, token: str) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE webhooks SET token = ? WHERE id = ?', (token, webhook_id))
            updated = cursor.rowcount
            conn.commit()
            return updated
        finally:
            conn.close()
