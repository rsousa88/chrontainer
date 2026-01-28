from __future__ import annotations

from app.repositories import ScheduleRepository


class ScheduleService:
    """Schedule business logic."""

    def __init__(self, schedule_repo: ScheduleRepository):
        self._schedule_repo = schedule_repo
