"""Tests for image management endpoints"""
import json


def test_images_requires_auth(client):
    """Images endpoint should require authentication"""
    response = client.get('/api/images')
    assert response.status_code in [302, 401]


def test_images_returns_list(authenticated_client, monkeypatch):
    """Images endpoint should return a list"""
    import main

    monkeypatch.setattr(main.docker_manager, 'get_all_clients', lambda: [])
    response = authenticated_client.get('/api/images')
    data = json.loads(response.data)
    assert isinstance(data, list)


def test_pull_requires_auth(client):
    """Image pull should require authentication"""
    response = client.post('/api/images/pull', json={'image': 'alpine:latest', 'host_id': 1})
    assert response.status_code in [302, 401]


def test_prune_requires_auth(client):
    """Image prune should require authentication"""
    response = client.post('/api/images/prune', json={'host_id': 1})
    assert response.status_code in [302, 401]


def test_delete_requires_auth(client):
    """Image delete should require authentication"""
    response = client.delete('/api/images/sha256:deadbeef', query_string={'host_id': 1})
    assert response.status_code in [302, 401]
