"""Tests for API deprecation headers"""


def test_legacy_api_sets_deprecation_headers(authenticated_client):
    response = authenticated_client.get('/api/settings')
    assert response.status_code == 200
    assert response.headers.get('X-Api-Deprecated') == 'true'
    assert response.headers.get('X-Api-Deprecation-Notice')


def test_v1_api_skips_deprecation_headers(authenticated_client):
    response = authenticated_client.get('/api/v1/settings')
    assert response.status_code == 200
    assert response.headers.get('X-Api-Deprecated') is None
