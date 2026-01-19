"""
Tests for health and version endpoints
"""
import json


class TestHealthEndpoint:
    """Tests for /health endpoint"""

    def test_health_endpoint_returns_200(self, client):
        """Health endpoint should return 200 when healthy"""
        response = client.get('/health')
        assert response.status_code == 200

    def test_health_endpoint_returns_json(self, client):
        """Health endpoint should return JSON"""
        response = client.get('/health')
        assert response.content_type == 'application/json'

    def test_health_endpoint_contains_status(self, client):
        """Health endpoint should contain status field"""
        response = client.get('/health')
        data = json.loads(response.data)
        assert 'status' in data
        assert data['status'] in ['healthy', 'degraded', 'unhealthy']

    def test_health_endpoint_contains_version(self, client):
        """Health endpoint should contain version field"""
        response = client.get('/health')
        data = json.loads(response.data)
        assert 'version' in data

    def test_health_endpoint_contains_checks(self, client):
        """Health endpoint should contain checks object"""
        response = client.get('/health')
        data = json.loads(response.data)
        assert 'checks' in data
        assert isinstance(data['checks'], dict)

    def test_health_endpoint_checks_database(self, client):
        """Health endpoint should check database"""
        response = client.get('/health')
        data = json.loads(response.data)
        assert 'database' in data['checks']
        assert data['checks']['database']['status'] == 'ok'

    def test_health_endpoint_checks_scheduler(self, client):
        """Health endpoint should check scheduler"""
        response = client.get('/health')
        data = json.loads(response.data)
        assert 'scheduler' in data['checks']


class TestVersionEndpoint:
    """Tests for /api/version endpoint"""

    def test_version_endpoint_returns_200(self, client):
        """Version endpoint should return 200"""
        response = client.get('/api/version')
        assert response.status_code == 200

    def test_version_endpoint_returns_json(self, client):
        """Version endpoint should return JSON"""
        response = client.get('/api/version')
        assert response.content_type == 'application/json'

    def test_version_endpoint_contains_version(self, client):
        """Version endpoint should contain version field"""
        response = client.get('/api/version')
        data = json.loads(response.data)
        assert 'version' in data
        assert isinstance(data['version'], str)

    def test_version_endpoint_contains_python_version(self, client):
        """Version endpoint should contain python_version field"""
        response = client.get('/api/version')
        data = json.loads(response.data)
        assert 'python_version' in data

    def test_version_endpoint_contains_api_version(self, client):
        """Version endpoint should contain api_version field"""
        response = client.get('/api/version')
        data = json.loads(response.data)
        assert 'api_version' in data
        assert data['api_version'] == 'v1'

    def test_version_endpoint_contains_stats(self, client):
        """Version endpoint should contain schedule and host counts"""
        response = client.get('/api/version')
        data = json.loads(response.data)
        assert 'active_schedules' in data
        assert 'active_hosts' in data
        assert isinstance(data['active_schedules'], int)
        assert isinstance(data['active_hosts'], int)
