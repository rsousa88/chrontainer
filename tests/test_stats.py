"""Tests for container stats endpoints"""
import json


class TestStatsEndpoint:
    """Tests for /api/container/<id>/stats endpoint"""

    def test_stats_endpoint_requires_auth(self, client):
        """Stats endpoint should require authentication"""
        response = client.get('/api/container/abc123/stats?host_id=1')
        assert response.status_code == 302

    def test_stats_endpoint_returns_json(self, authenticated_client):
        """Stats endpoint should return JSON"""
        response = authenticated_client.get('/api/container/abc123/stats?host_id=1')
        assert response.content_type == 'application/json'


class TestBulkStatsEndpoint:
    """Tests for /api/containers/stats endpoint"""

    def test_bulk_stats_requires_auth(self, client):
        """Bulk stats should require authentication"""
        response = client.get('/api/containers/stats')
        assert response.status_code == 302

    def test_bulk_stats_returns_dict(self, authenticated_client):
        """Bulk stats should return a dictionary"""
        response = authenticated_client.get('/api/containers/stats')
        data = json.loads(response.data)
        assert isinstance(data, dict)
