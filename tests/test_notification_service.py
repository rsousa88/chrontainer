"""Tests for notification service formatting and settings usage."""

from app.repositories import SettingsRepository
from app.services.notification_service import NotificationService
from app.db import get_db


def test_discord_notification_includes_username_and_avatar(app, monkeypatch):
    settings = SettingsRepository(get_db)
    settings.set('discord_webhook_url', 'https://discord.com/api/webhooks/123/abc')
    settings.set('discord_username', 'Chrontainer')
    settings.set('discord_avatar_url', 'https://example.com/avatar.png')

    sent = {}

    def fake_post(url, json=None, timeout=10):
        sent['url'] = url
        sent['payload'] = json
        class Resp:
            status_code = 204
        return Resp()

    monkeypatch.setattr('app.services.notification_service.requests.post', fake_post)

    service = NotificationService(settings)
    service.send_discord_notification('container', 'restart', 'success', 'ok')

    assert sent['url'].startswith('https://discord.com/api/webhooks/')
    assert sent['payload']['username'] == 'Chrontainer'
    assert sent['payload']['avatar_url'] == 'https://example.com/avatar.png'


def test_ntfy_notification_uses_token(app, monkeypatch):
    settings = SettingsRepository(get_db)
    settings.set('ntfy_enabled', 'true')
    settings.set('ntfy_server', 'https://ntfy.sh')
    settings.set('ntfy_topic', 'chrontainer')
    settings.set('ntfy_access_token', 'secret')

    headers_seen = {}

    def fake_post(url, data=None, headers=None, timeout=10):
        headers_seen['headers'] = headers
        class Resp:
            status_code = 200
        return Resp()

    monkeypatch.setattr('app.services.notification_service.requests.post', fake_post)

    service = NotificationService(settings)
    service.send_ntfy_notification('container', 'restart', 'success', 'ok')

    assert headers_seen['headers']['Authorization'] == 'Bearer secret'
