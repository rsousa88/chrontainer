"""Tests for schedule endpoints"""
import json
from datetime import datetime, timedelta


class TestOneTimeSchedules:
    """Tests for one-time schedules"""

    def test_create_one_time_schedule(self, authenticated_client):
        """Should create a one-time schedule"""
        future_time = (datetime.now() + timedelta(hours=1)).isoformat()
        response = authenticated_client.post(
            '/api/schedule',
            json={
                'container_id': 'a' * 12,
                'container_name': 'test-container',
                'host_id': 1,
                'action': 'restart',
                'one_time': True,
                'run_at': future_time
            },
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert response.status_code == 200
        assert 'schedule_id' in data

    def test_one_time_schedule_requires_run_at(self, authenticated_client):
        """One-time schedule should require run_at"""
        response = authenticated_client.post(
            '/api/schedule',
            json={
                'container_id': 'a' * 12,
                'container_name': 'test-container',
                'host_id': 1,
                'action': 'restart',
                'one_time': True
            },
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_one_time_schedule_rejects_past_time(self, authenticated_client):
        """One-time schedule should reject past times"""
        past_time = (datetime.now() - timedelta(hours=1)).isoformat()
        response = authenticated_client.post(
            '/api/schedule',
            json={
                'container_id': 'a' * 12,
                'container_name': 'test-container',
                'host_id': 1,
                'action': 'restart',
                'one_time': True,
                'run_at': past_time
            },
            content_type='application/json'
        )
        assert response.status_code == 400
