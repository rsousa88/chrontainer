"""Routes package (blueprints will live here)."""
from .api_keys import create_api_keys_blueprint
from .auth import create_auth_blueprint
from .health import create_health_blueprint
from .hosts import create_hosts_blueprint
from .images import create_images_blueprint
from .logs import create_logs_blueprint
from .settings import create_settings_blueprint
from .webhooks import create_webhooks_blueprint

__all__ = [
    'create_auth_blueprint',
    'create_api_keys_blueprint',
    'create_health_blueprint',
    'create_hosts_blueprint',
    'create_images_blueprint',
    'create_logs_blueprint',
    'create_settings_blueprint',
    'create_webhooks_blueprint',
]
