from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

import sqlite3


class ScheduleRepository:
    """Repository for schedules.""""
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
