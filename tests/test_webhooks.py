"""Tests for webhook functionality"""
import json


class TestWebhookManagement:
    """Tests for webhook CRUD"""

    def test_create_webhook(self, authenticated_client):
        """Should create a webhook"""
        response = authenticated_client.post(
            '/api/webhooks',
            json={'name': 'Test Webhook', 'action': 'restart'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert response.status_code == 200
        assert 'token' in data
        assert 'url' in data

    def test_list_webhooks(self, authenticated_client):
        """Should list webhooks"""
        authenticated_client.post(
            '/api/webhooks',
            json={'name': 'Test', 'action': 'restart'},
            content_type='application/json'
        )

        response = authenticated_client.get('/api/webhooks')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert isinstance(data, list)


class TestWebhookTrigger:
    """Tests for webhook triggering"""

    def test_invalid_token_rejected(self, client):
        """Invalid webhook token should return 404"""
        response = client.post('/webhook/invalid_token_12345')
        assert response.status_code == 404

    def test_disabled_webhook_rejected(self, authenticated_client, client):
        """Disabled webhook should return 403"""
        response = authenticated_client.post(
            '/api/webhooks',
            json={'name': 'Test', 'action': 'restart', 'container_id': 'abc123'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        webhook_id = data['id']
        token = data['token']

        authenticated_client.post(f'/api/webhooks/{webhook_id}/toggle')

        response = client.post(f'/webhook/{token}')
        assert response.status_code == 403


class TestWebhookLock:
    """Tests for webhook lock functionality"""

    def test_create_locked_webhook(self, authenticated_client):
        """Should create a locked webhook"""
        response = authenticated_client.post(
            '/api/webhooks',
            json={'name': 'Locked Webhook', 'action': 'restart', 'locked': True},
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert response.status_code == 200
        assert data['locked'] is True

    def test_toggle_webhook_lock(self, authenticated_client):
        """Should toggle webhook lock status"""
        # Create webhook
        response = authenticated_client.post(
            '/api/webhooks',
            json={'name': 'Test', 'action': 'restart'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        webhook_id = data['id']

        # Toggle lock on
        response = authenticated_client.post(f'/api/webhooks/{webhook_id}/lock')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert data['locked'] is True

        # Toggle lock off
        response = authenticated_client.post(f'/api/webhooks/{webhook_id}/lock')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert data['locked'] is False


class TestWebhookTokenRegeneration:
    """Tests for webhook token regeneration"""

    def test_regenerate_token(self, authenticated_client):
        """Should regenerate webhook token"""
        # Create webhook
        response = authenticated_client.post(
            '/api/webhooks',
            json={'name': 'Test', 'action': 'restart'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        webhook_id = data['id']
        old_token = data['token']

        # Regenerate token
        response = authenticated_client.post(f'/api/webhooks/{webhook_id}/regenerate')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert data['success'] is True
        assert 'token' in data
        assert data['token'] != old_token
        assert 'url' in data

    def test_old_token_invalid_after_regeneration(self, authenticated_client, client):
        """Old token should be invalid after regeneration"""
        # Create webhook with container
        response = authenticated_client.post(
            '/api/webhooks',
            json={'name': 'Test', 'action': 'restart', 'container_id': 'abc123'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        webhook_id = data['id']
        old_token = data['token']

        # Regenerate token
        authenticated_client.post(f'/api/webhooks/{webhook_id}/regenerate')

        # Old token should now be invalid
        response = client.post(f'/webhook/{old_token}')
        assert response.status_code == 404
