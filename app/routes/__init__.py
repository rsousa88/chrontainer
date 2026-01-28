"""Routes package (blueprints will live here)."""
from .auth import create_auth_blueprint
from .health import create_health_blueprint

__all__ = [
    'create_auth_blueprint',
    'create_health_blueprint',
]
