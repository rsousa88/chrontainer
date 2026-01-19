"""Tests for host metrics endpoints"""
import json


class TestHostMetrics:
    """Tests for host metrics endpoints"""

    def test_metrics_requires_auth(self, client):
        """Host metrics should require authentication"""
        response = client.get('/api/hosts/1/metrics')
        assert response.status_code in [302, 401]

    def test_all_hosts_metrics(self, authenticated_client):
        """Should return metrics for all hosts"""
        response = authenticated_client.get('/api/hosts/metrics')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert isinstance(data, list)

    def test_single_host_metrics(self, authenticated_client):
        """Should return detailed metrics for a single host"""
        response = authenticated_client.get('/api/hosts/1/metrics')
        assert response.status_code in [200, 503]


class TestMetricsPage:
    """Tests for metrics page"""

    def test_metrics_page_requires_auth(self, client):
        """Metrics page should require authentication"""
        response = client.get('/metrics')
        assert response.status_code == 302

    def test_metrics_page_loads(self, authenticated_client):
        """Metrics page should load for authenticated users"""
        response = authenticated_client.get('/metrics')
        assert response.status_code == 200
        assert b'Host Metrics' in response.data
