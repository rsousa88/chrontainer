"""Tests for container action endpoints"""


def test_delete_container_requires_auth(client):
    """Delete container should require authentication"""
    response = client.post('/api/container/abcdef123456/delete', json={'name': 'test', 'host_id': 1})
    assert response.status_code in [302, 401]


def test_delete_container_invalid_id(authenticated_client):
    """Delete container should validate container ID format"""
    response = authenticated_client.post('/api/container/not-a-valid-id/delete', json={'name': 'test', 'host_id': 1})
    assert response.status_code == 400
