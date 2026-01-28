from __future__ import annotations

import sqlite3
from typing import Callable, Iterable


class BaseRepository:
    """Base repository with helper to run queries.""""
    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self._db_factory = db_factory

    def _execute(self, query: str, params: Iterable = ()):  # pragma: no cover - placeholder
        conn = self._db_factory()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor
        finally:
            conn.close()
