"""Tests for API auth endpoints"""


def test_api_login_success(client):
    response = client.post('/api/login', data={
        'username': 'admin',
        'password': 'admin',
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
    assert data['username'] == 'admin'


def test_api_user_requires_login(client):
    response = client.get('/api/user')
    assert response.status_code == 302


def test_api_user_after_login(client):
    login = client.post('/api/login', data={
        'username': 'admin',
        'password': 'admin',
    })
    assert login.status_code == 200
    response = client.get('/api/user')
    assert response.status_code == 200
    data = response.get_json()
    assert data['username'] == 'admin'


def test_api_logout(client):
    client.post('/api/login', data={
        'username': 'admin',
        'password': 'admin',
    })
    response = client.post('/api/logout')
    assert response.status_code == 200
    data = response.get_json()
    assert data['success'] is True
