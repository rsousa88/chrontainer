from __future__ import annotations

from datetime import datetime

import requests

from app.repositories import SettingsRepository


class NotificationService:
    """Notification dispatch logic."""

    def __init__(self, settings_repo: SettingsRepository):
        self._settings_repo = settings_repo

    def _get_setting(self, key: str, default: str | None = None) -> str | None:
        value = self._settings_repo.get(key)
        return value if value is not None else default

    def send_discord_notification(
        self,
        container_name: str,
        action: str,
        status: str,
        message: str,
        schedule_id: int | None = None,
    ) -> None:
        webhook_url = self._get_setting('discord_webhook_url')
        if not webhook_url:
            return

        try:
            if status == 'success':
                emoji = '✅'
                color = 0x00FF00
            else:
                emoji = '❌'
                color = 0xFF0000

            embed = {
                'title': f'{emoji} Container Action: {action.capitalize()}',
                'description': message,
                'color': color,
                'fields': [
                    {'name': 'Container', 'value': container_name, 'inline': True},
                    {'name': 'Action', 'value': action.capitalize(), 'inline': True},
                    {'name': 'Status', 'value': status.capitalize(), 'inline': True},
                ],
                'timestamp': datetime.utcnow().isoformat(),
                'footer': {'text': 'Chrontainer'},
            }

            if schedule_id:
                embed['fields'].append({'name': 'Schedule ID', 'value': str(schedule_id), 'inline': True})

            payload = {'embeds': [embed]}

            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code not in [200, 204]:
                # best-effort; ignore
                pass
        except Exception:
            # best-effort; ignore errors
            return

    def send_ntfy_notification(
        self,
        container_name: str,
        action: str,
        status: str,
        message: str,
        schedule_id: int | None = None,
    ) -> None:
        _ = schedule_id  # unused, kept for parity with discord signature
        ntfy_enabled = self._get_setting('ntfy_enabled', 'false')
        if ntfy_enabled != 'true':
            return

        ntfy_server = self._get_setting('ntfy_server', 'https://ntfy.sh')
        ntfy_topic = self._get_setting('ntfy_topic')

        if not ntfy_topic:
            return

        try:
            emoji = 'white_check_mark' if status == 'success' else 'x'
            title = f"Chrontainer: {action.capitalize()} {status.capitalize()}"
            body = f"{container_name}: {message}"
            url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"

            response = requests.post(
                url,
                data=body.encode('utf-8'),
                headers={
                    'Title': title,
                    'Priority': str(self._get_setting('ntfy_priority', '3')),
                    'Tags': emoji,
                },
                timeout=10,
            )
            if response.status_code not in [200, 204]:
                pass
        except Exception:
            return
