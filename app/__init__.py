from __future__ import annotations

from app.main import app as _app


def create_app():
    """Return the configured Flask app."""
    return _app
