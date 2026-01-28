from __future__ import annotations

from datetime import datetime

from app.models import ApiKey, Container, Host, Image, Schedule, User, Webhook


def test_models_can_be_instantiated():
    now = datetime.utcnow()

    container = Container(id='abc123', name='app', image='nginx:latest', status='running', host_id=1)
    assert container.name == 'app'

    schedule = Schedule(
        id=1,
        host_id=1,
        container_id='abc123',
        container_name='app',
        action='restart',
        cron_expression='0 2 * * *',
        enabled=True,
        one_time=False,
        run_at=None,
        last_run=now,
    )
    assert schedule.action == 'restart'

    host = Host(id=1, name='local', url='unix:///var/run/docker.sock', enabled=True)
    assert host.enabled is True

    user = User(id=1, username='admin', role='admin', created_at=now)
    assert user.role == 'admin'

    image = Image(id='sha256:deadbeef', repository='nginx', tag='latest', host_id=1)
    assert image.repository == 'nginx'

    api_key = ApiKey(id=1, user_id=1, key_hash='hash', permissions='read')
    assert api_key.permissions == 'read'

    webhook = Webhook(id=1, name='hook', token='tok', container_id=None, host_id=None, action='restart')
    assert webhook.action == 'restart'
