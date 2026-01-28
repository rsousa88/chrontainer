from __future__ import annotations

from app.repositories import ScheduleRepository


class ScheduleService:
    """Schedule business logic."""

    def __init__(self, schedule_repo: ScheduleRepository):
        self._schedule_repo = schedule_repo

    def create(self, **kwargs):
        return self._schedule_repo.create(**kwargs)

    def delete(self, schedule_id: int) -> None:
        self._schedule_repo.delete(schedule_id)

    def toggle(self, schedule_id: int) -> int:
        return self._schedule_repo.toggle_enabled(schedule_id)

    def list_enabled(self):
        return self._schedule_repo.list_enabled()
