"""repositories package."""
from .api_keys import ApiKeyRepository
from .app_logs import AppLogRepository
from .container_tags import ContainerTagRepository
from .hosts import HostRepository
from .hosts_metrics import HostMetricsRepository
from .login import LoginRepository
from .logs import LogsRepository
from .schedules import ScheduleRepository
from .schedules_view import ScheduleViewRepository
from .settings import SettingsRepository
from .stats import StatsRepository
from .tags import TagRepository
from .update_status import UpdateStatusRepository
from .users import UserRepository
from .webhooks import WebhookRepository
from .webui_urls import WebuiUrlRepository

__all__ = [
    'ApiKeyRepository',
    'AppLogRepository',
    'ContainerTagRepository',
    'HostMetricsRepository',
    'HostRepository',
    'LoginRepository',
    'LogsRepository',
    'ScheduleRepository',
    'ScheduleViewRepository',
    'SettingsRepository',
    'StatsRepository',
    'TagRepository',
    'UpdateStatusRepository',
    'UserRepository',
    'WebhookRepository',
    'WebuiUrlRepository',
]
