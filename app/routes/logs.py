from __future__ import annotations

from pathlib import Path
from flask import Blueprint, jsonify, render_template, send_from_directory
from flask_login import login_required


def create_logs_blueprint(app_log_repo, host_repo, version: str):
    """Create logs routes with injected dependencies."""
    blueprint = Blueprint('logs', __name__)
    dist_dir = Path(__file__).resolve().parents[3] / 'frontend' / 'dist'

    @blueprint.route('/logs')
    @login_required
    def logs():
        """View logs page."""
        if dist_dir.joinpath('index.html').exists():
            return send_from_directory(dist_dir, 'index.html')
        logs_data = app_log_repo.list_recent(100)
        return render_template('logs.html', logs=logs_data, version=version)

    @blueprint.route('/api/logs', methods=['GET'])
    @login_required
    def logs_api():
        """Return recent application logs."""
        try:
            logs_data = app_log_repo.list_recent(100)
            hosts = {row[0]: row[1] for row in host_repo.list_all()}
            payload = [
                {
                    'id': row[0],
                    'schedule_id': row[1],
                    'host_id': row[2],
                    'host_name': hosts.get(row[2]),
                    'container_name': row[3],
                    'action': row[4],
                    'status': row[5],
                    'message': row[6],
                    'timestamp': row[7],
                }
                for row in logs_data
            ]
            return jsonify(payload)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return blueprint
