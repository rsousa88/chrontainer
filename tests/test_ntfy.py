"""Tests for ntfy settings endpoints"""


class TestNtfySettings:
    """Tests for /api/settings/ntfy endpoint"""

    def test_ntfy_settings_requires_auth(self, client):
        """ntfy settings update should require authentication"""
        response = client.post('/api/settings/ntfy', json={})
        assert response.status_code == 302

    def test_ntfy_settings_update(self, authenticated_client):
        """ntfy settings update should accept valid payload"""
        response = authenticated_client.post('/api/settings/ntfy', json={
            'enabled': False,
            'server': 'https://ntfy.sh',
            'topic': '',
            'priority': 3
        })
        assert response.status_code == 200
