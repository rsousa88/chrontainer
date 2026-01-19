"""
Tests for authentication endpoints
"""
import json


class TestLoginEndpoint:
    """Tests for /login endpoint"""

    def test_login_page_returns_200(self, client):
        """Login page should be accessible"""
        response = client.get('/login')
        assert response.status_code == 200

    def test_login_with_valid_credentials(self, client):
        """Login with valid credentials should succeed"""
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=True)
        assert response.status_code == 200

    def test_login_with_invalid_credentials(self, client):
        """Login with invalid credentials should fail"""
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'wrongpassword'
        }, follow_redirects=True)
        assert b'Invalid username or password' in response.data

    def test_login_with_empty_credentials(self, client):
        """Login with empty credentials should fail"""
        response = client.post('/login', data={
            'username': '',
            'password': ''
        }, follow_redirects=True)
        assert b'Please enter both username and password' in response.data


class TestLogoutEndpoint:
    """Tests for /logout endpoint"""

    def test_logout_redirects_to_login(self, authenticated_client):
        """Logout should redirect to login page"""
        response = authenticated_client.get('/logout', follow_redirects=True)
        assert response.status_code == 200
        assert b'login' in response.data.lower() or b'You have been logged out' in response.data


class TestProtectedEndpoints:
    """Tests for protected endpoints"""

    def test_index_requires_login(self, client):
        """Index page should require login"""
        response = client.get('/')
        # Should redirect to login
        assert response.status_code == 302
        assert '/login' in response.headers.get('Location', '')

    def test_settings_requires_login(self, client):
        """Settings page should require login"""
        response = client.get('/settings')
        assert response.status_code == 302
        assert '/login' in response.headers.get('Location', '')

    def test_logs_requires_login(self, client):
        """Logs page should require login"""
        response = client.get('/logs')
        assert response.status_code == 302
        assert '/login' in response.headers.get('Location', '')

    def test_authenticated_user_can_access_index(self, authenticated_client):
        """Authenticated user should be able to access index"""
        response = authenticated_client.get('/')
        assert response.status_code == 200
