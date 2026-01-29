"""Tests for settings API endpoints"""


def test_get_settings_requires_auth(client):
    response = client.get('/api/settings')
    assert response.status_code == 302


def test_get_settings_returns_defaults(authenticated_client):
    response = authenticated_client.get('/api/settings')
    assert response.status_code == 200
    data = response.get_json()
    assert 'discord_webhook_url' in data
    assert 'discord_username' in data
    assert 'discord_avatar_url' in data
    assert 'ntfy_access_token' in data


def test_save_discord_with_metadata(authenticated_client):
    payload = {
        'webhook_url': 'https://discord.com/api/webhooks/123/abc',
        'username': 'Chrontainer',
        'avatar_url': 'https://example.com/avatar.png',
    }
    response = authenticated_client.post('/api/settings/discord', json=payload)
    assert response.status_code == 200

    settings = authenticated_client.get('/api/settings').get_json()
    assert settings['discord_webhook_url'] == payload['webhook_url']
    assert settings['discord_username'] == payload['username']
    assert settings['discord_avatar_url'] == payload['avatar_url']


def test_save_discord_rejects_bad_avatar(authenticated_client):
    payload = {
        'webhook_url': 'https://discord.com/api/webhooks/123/abc',
        'username': 'Chrontainer',
        'avatar_url': 'not-a-url',
    }
    response = authenticated_client.post('/api/settings/discord', json=payload)
    assert response.status_code == 400


def test_ntfy_access_token_persists(authenticated_client):
    payload = {
        'enabled': True,
        'server': 'https://ntfy.sh',
        'topic': 'chrontainer',
        'priority': 3,
        'access_token': 'abc123',
    }
    response = authenticated_client.post('/api/settings/ntfy', json=payload)
    assert response.status_code == 200

    settings = authenticated_client.get('/api/settings').get_json()
    assert settings['ntfy_access_token'] == 'abc123'
