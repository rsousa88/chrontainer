from __future__ import annotations

from app.services.auth_service import AuthService
from app.services.schedule_service import ScheduleService


class DummyUserRepo:
    def __init__(self):
        self.calls = []

    def get_by_id(self, user_id):
        self.calls.append(('get_by_id', user_id))
        return (user_id, 'user', 'admin')


class DummyApiKeyRepo:
    def __init__(self):
        self.calls = []

    def get_auth_record(self, key_hash):
        self.calls.append(('get_auth_record', key_hash))
        return (1, 1, 'read', None, 'admin')

    def touch_last_used(self, key_id):
        self.calls.append(('touch_last_used', key_id))


class DummyScheduleRepo:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(('create', kwargs))
        return 42

    def delete(self, schedule_id):
        self.calls.append(('delete', schedule_id))

    def toggle_enabled(self, schedule_id):
        self.calls.append(('toggle_enabled', schedule_id))
        return 1

    def list_enabled(self):
        self.calls.append(('list_enabled',))
        return []


def test_auth_service_delegates():
    user_repo = DummyUserRepo()
    api_repo = DummyApiKeyRepo()
    service = AuthService(user_repo, api_repo)

    assert service.get_user_by_id(1)[0] == 1
    assert service.get_api_key_record('hash')[0] == 1
    service.touch_api_key(5)

    assert ('get_by_id', 1) in user_repo.calls
    assert ('get_auth_record', 'hash') in api_repo.calls
    assert ('touch_last_used', 5) in api_repo.calls


def test_schedule_service_delegates():
    repo = DummyScheduleRepo()
    service = ScheduleService(repo)

    assert service.create(host_id=1, container_id='abc', container_name='c', action='restart', cron_expression='* * * * *') == 42
    service.delete(1)
    assert service.toggle(2) == 1
    assert service.list_enabled() == []

    assert ('create',) == (repo.calls[0][0],)
    assert ('delete', 1) in repo.calls
    assert ('toggle_enabled', 2) in repo.calls
    assert ('list_enabled',) in repo.calls
