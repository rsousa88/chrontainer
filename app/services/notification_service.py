from __future__ import annotations

from app.repositories import SettingsRepository


class NotificationService:
    """Notification dispatch logic."""

    def __init__(self, settings_repo: SettingsRepository):
        self._settings_repo = settings_repo
