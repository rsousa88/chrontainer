from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

import sqlite3


class ScheduleRepository:
    """Repository for schedules."""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def list_enabled(self):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, host_id, container_id, container_name, action, cron_expression, one_time, run_at '
                'FROM schedules WHERE enabled = 1'
            )
            return cursor.fetchall()
        finally:
            conn.close()

    def create(
        self,
        host_id: int,
        container_id: str,
        container_name: str,
        action: str,
        cron_expression: str,
        one_time: int,
        run_at: str | None,
    ) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO schedules
                   (host_id, container_id, container_name, action, cron_expression, one_time, run_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (
                    host_id,
                    container_id,
                    container_name,
                    action,
                    cron_expression,
                    one_time,
                    run_at,
                ),
            )
            schedule_id = cursor.lastrowid
            conn.commit()
            return schedule_id
        finally:
            conn.close()

    def delete(self, schedule_id: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM schedules WHERE id = ?', (schedule_id,))
            conn.commit()
        finally:
            conn.close()

    def update_last_run(self, schedule_id: int, last_run: datetime) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE schedules SET last_run = ? WHERE id = ?',
                (last_run, schedule_id),
            )
            conn.commit()
        finally:
            conn.close()

    def get_by_id(self, schedule_id: int):
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT enabled, host_id, container_id, container_name, action, cron_expression, one_time, run_at '
                'FROM schedules WHERE id = ?',
                (schedule_id,),
            )
            return cursor.fetchone()
        finally:
            conn.close()

    def set_enabled(self, schedule_id: int, enabled: int) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE schedules SET enabled = ? WHERE id = ?', (enabled, schedule_id))
            conn.commit()
        finally:
            conn.close()

    def count_by_host(self, host_id: int) -> int:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM schedules WHERE host_id = ?', (host_id,))
            return cursor.fetchone()[0]
        finally:
            conn.close()

    def update_container_id(self, schedule_id: int, container_id: str) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE schedules SET container_id = ? WHERE id = ?', (container_id, schedule_id))
            conn.commit()
        finally:
            conn.close()

    def update_schedule(
        self,
        schedule_id: int,
        *,
        host_id: int,
        container_id: str,
        container_name: str,
        action: str,
        cron_expression: str,
        one_time: int,
        run_at: str | None,
        enabled: int,
    ) -> None:
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                UPDATE schedules
                SET host_id = ?,
                    container_id = ?,
                    container_name = ?,
                    action = ?,
                    cron_expression = ?,
                    one_time = ?,
                    run_at = ?,
                    enabled = ?
                WHERE id = ?
                ''',
                (
                    host_id,
                    container_id,
                    container_name,
                    action,
                    cron_expression,
                    one_time,
                    run_at,
                    enabled,
                    schedule_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def update_container_name(self, host_id: int, container_id: str, old_name: str, new_name: str) -> int:
        short_id = (container_id or '')[:12]
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                UPDATE schedules
                SET container_name = ?
                WHERE host_id = ?
                  AND (container_id = ? OR container_id = ? OR container_name = ?)
                ''',
                (new_name, host_id, container_id, short_id, old_name)
            )
            affected = cursor.rowcount
            conn.commit()
            return affected
        finally:
            conn.close()

    def disable_by_container(self, host_id: int, container_id: str, container_name: str) -> int:
        short_id = (container_id or '')[:12]
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                UPDATE schedules
                SET enabled = 0
                WHERE host_id = ?
                  AND (container_id = ? OR container_id = ? OR container_name = ?)
                ''',
                (host_id, container_id, short_id, container_name)
            )
            affected = cursor.rowcount
            conn.commit()
            return affected
        finally:
            conn.close()
