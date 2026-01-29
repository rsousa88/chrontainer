from __future__ import annotations

from flask import Blueprint, jsonify, render_template
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

    @blueprint.route('/api/logs', methods=['GET'])
    @login_required
    def logs_api():
        """Return recent application logs."""
        try:
            logs_data = app_log_repo.list_recent(100)
            payload = [
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'level': row[2],
                    'message': row[3],
                    'details': row[4],
                }
                for row in logs_data
            ]
            return jsonify(payload)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return blueprint
