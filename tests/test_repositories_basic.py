"""Repository coverage tests for core persistence layers."""

from datetime import datetime

from app.db import get_db
from app.repositories import (
    HostRepository,
    TagRepository,
    ContainerTagRepository,
    LogsRepository,
    AppLogRepository,
    WebuiUrlRepository,
    UpdateStatusRepository,
    UserRepository,
    ScheduleRepository,
)


def test_host_repository_crud(app):
    repo = HostRepository(get_db)
    host_id = repo.create('local-test', 'unix:///var/run/docker.sock', '#123456', datetime.utcnow())
    assert isinstance(host_id, int)

    row = repo.get_by_id(host_id)
    assert row[1] == 'local-test'

    repo.update(host_id, 'local-new', 'tcp://127.0.0.1:2375', 1, '#ffffff')
    assert repo.get_by_id(host_id)[1] == 'local-new'

    assert repo.get_url(host_id) == 'tcp://127.0.0.1:2375'
    repo.set_enabled(host_id, 0)
    assert repo.get_by_id(host_id)[3] == 0

    repo.delete(host_id)
    assert repo.get_by_id(host_id) is None


def test_tag_and_container_tag_repository(app):
    tag_repo = TagRepository(get_db)
    ct_repo = ContainerTagRepository(get_db)

    tag_id = tag_repo.create('media', '#ff0000')
    assert tag_id > 0

    ct_repo.add('abc123', 1, tag_id)
    tags = ct_repo.list_for_container('abc123', 1)
    assert tags and tags[0][0] == tag_id

    ct_repo.remove('abc123', 1, tag_id)
    assert ct_repo.list_for_container('abc123', 1) == []

    tag_repo.delete(tag_id)


def test_logs_repositories(app):
    logs_repo = LogsRepository(get_db)
    app_logs_repo = AppLogRepository(get_db)

    logs_repo.insert_action_log(None, 'container', 'restart', 'success', 'details')
    app_recent = app_logs_repo.list_recent(5)
    assert app_recent


def test_webui_and_update_status_repositories(app):
    webui_repo = WebuiUrlRepository(get_db)
    update_repo = UpdateStatusRepository(get_db)

    webui_repo.upsert('abc', 1, 'http://example.com')
    assert webui_repo.get('abc', 1) == 'http://example.com'

    update_repo.upsert('abc', 1, True, 'sha_remote', None, 'note', 'now')
    status = update_repo.list_all()[0]
    assert status[0] == 'abc'


def test_user_and_schedule_repositories(app):
    user_repo = UserRepository(get_db)
    assert user_repo.get_by_id(1)[1] == 'admin'

    schedule_repo = ScheduleRepository(get_db)
    schedule_id = schedule_repo.create(
        host_id=1,
        container_id='abc123',
        container_name='demo',
        action='restart',
        cron_expression='0 2 * * *',
        one_time=0,
        run_at=None,
    )
    assert schedule_repo.get_by_id(schedule_id)[2] == 'abc123'
    schedule_repo.set_enabled(schedule_id, 0)
    assert schedule_repo.get_by_id(schedule_id)[0] == 0

    schedule_repo.update_container_id(schedule_id, 'def456')
    assert schedule_repo.get_by_id(schedule_id)[2] == 'def456'

    schedule_repo.update_container_name(1, 'def456', 'demo', 'demo-2')
    schedule_repo.disable_by_container(1, 'def456', 'demo-2')

    schedule_repo.delete(schedule_id)
