"""Tests for API key authentication"""
import json


class TestApiKeyEndpoints:
    """Tests for API key management endpoints"""

    def test_list_keys_requires_auth(self, client):
        """List keys endpoint requires authentication"""
        response = client.get('/api/keys')
        assert response.status_code == 302

    def test_create_key(self, authenticated_client):
        """Should create an API key"""
        response = authenticated_client.post(
            '/api/keys',
            json={'name': 'Test Key', 'permissions': 'read'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert response.status_code == 200
        assert 'key' in data
        assert data['key'].startswith('chron_')
        assert len(data['key']) == 36

    def test_create_key_returns_key_only_once(self, authenticated_client):
        """Key should only be visible on creation"""
        response = authenticated_client.post(
            '/api/keys',
            json={'name': 'Test Key', 'permissions': 'read'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert 'key' in data

        response = authenticated_client.get('/api/keys')
        keys = json.loads(response.data)
        assert len(keys) > 0
        assert 'key' not in keys[0]

    def test_invalid_permissions_rejected(self, authenticated_client):
        """Invalid permissions should be rejected"""
        response = authenticated_client.post(
            '/api/keys',
            json={'name': 'Test Key', 'permissions': 'superadmin'},
            content_type='application/json'
        )
        assert response.status_code == 400


class TestApiKeyAuth:
    """Tests for API key authentication on endpoints"""

    def test_hosts_endpoint_accepts_api_key(self, app, authenticated_client):
        """Hosts endpoint should accept API key"""
        response = authenticated_client.post(
            '/api/keys',
            json={'name': 'Test Key', 'permissions': 'read'},
            content_type='application/json'
        )
        key = json.loads(response.data)['key']

        with app.test_client() as client:
            response = client.get('/api/hosts', headers={'X-API-Key': key})
            assert response.status_code == 200

    def test_invalid_api_key_rejected(self, app):
        """Invalid API key should be rejected"""
        with app.test_client() as client:
            response = client.get('/api/hosts', headers={'X-API-Key': 'chron_invalidkey12345678901234'})
            assert response.status_code == 401

    def test_read_key_cannot_write(self, app, authenticated_client):
        """Read-only key should not be able to perform write operations"""
        response = authenticated_client.post(
            '/api/keys',
            json={'name': 'Read Key', 'permissions': 'read'},
            content_type='application/json'
        )
        key = json.loads(response.data)['key']

        payload = {
            'container_id': 'abcdef123456',
            'container_name': 'testcontainer',
            'action': 'restart',
            'cron_expression': '0 2 * * *',
            'host_id': 1,
            'one_time': False
        }

        with app.test_client() as client:
            response = client.post(
                '/api/schedule',
                headers={'X-API-Key': key},
                json=payload,
                content_type='application/json'
            )
            assert response.status_code == 403
