from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required


def create_logs_blueprint(app_log_repo, version: str):
    """Create logs routes with injected dependencies."""
    blueprint = Blueprint('logs', __name__)

    @blueprint.route('/logs')
    @login_required
    def logs():
        """View logs page."""
        logs_data = app_log_repo.list_recent(100)
        return render_template('logs.html', logs=logs_data, version=version)

    return blueprint
