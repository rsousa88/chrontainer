from __future__ import annotations


def create_app():
    """Application factory."""
    from app.main import create_app as _create_app

    return _create_app()
