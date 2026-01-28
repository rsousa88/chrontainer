"""Application package for Chrontainer."""

from __future__ import annotations

from flask import Flask

from app.config import Config
from app.extensions import csrf, limiter, login_manager


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    csrf.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)

    return app
