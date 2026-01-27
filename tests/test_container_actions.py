"""Tests for container action endpoints"""


def test_delete_container_requires_auth(client):
    """Delete container should require authentication"""
    response = client.post('/api/container/abcdef123456/delete', json={'name': 'test', 'host_id': 1})
    assert response.status_code in [302, 401]


def test_delete_container_invalid_id(authenticated_client):
    """Delete container should validate container ID format"""
    response = authenticated_client.post('/api/container/not-a-valid-id/delete', json={'name': 'test', 'host_id': 1})
    assert response.status_code == 400


def test_rename_container_requires_auth(client):
    """Rename container should require authentication"""
    response = client.post('/api/container/abcdef123456/rename', json={'name': 'test', 'new_name': 'new', 'host_id': 1})
    assert response.status_code in [302, 401]


def test_rename_container_invalid_id(authenticated_client):
    """Rename container should validate container ID format"""
    response = authenticated_client.post('/api/container/not-a-valid-id/rename', json={'name': 'test', 'new_name': 'new', 'host_id': 1})
    assert response.status_code == 400


def test_rename_container_requires_new_name(authenticated_client):
    """Rename container should require a new name"""
    response = authenticated_client.post('/api/container/abcdef123456/rename', json={'name': 'test', 'host_id': 1})
    assert response.status_code == 400


def test_inspect_container_requires_auth(client):
    """Inspect container should require authentication"""
    response = client.get('/api/container/abcdef123456/inspect?host_id=1')
    assert response.status_code in [302, 401]


def test_inspect_container_invalid_id(authenticated_client):
    """Inspect container should validate container ID format"""
    response = authenticated_client.get('/api/container/not-a-valid-id/inspect?host_id=1')
    assert response.status_code == 400
