from __future__ import annotations

from typing import Callable

from flask import Blueprint, jsonify


def create_health_blueprint(stats_repo, docker_manager, scheduler, db_factory: Callable[[], object], version: str):
    """Create health and version routes with injected dependencies."""
    blueprint = Blueprint('health', __name__)

    @blueprint.route('/health')
    def health_check():
        """Health check endpoint for container orchestration and monitoring."""
        health = {
            'status': 'healthy',
            'version': version,
            'checks': {},
        }

        # Check database connectivity
        try:
            conn = db_factory()
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            conn.close()
            health['checks']['database'] = {'status': 'ok'}
        except Exception as e:
            health['status'] = 'unhealthy'
            health['checks']['database'] = {'status': 'error', 'message': str(e)}

        # Check scheduler status
        try:
            if scheduler.running:
                health['checks']['scheduler'] = {'status': 'ok', 'jobs': len(scheduler.get_jobs())}
            else:
                health['status'] = 'unhealthy'
                health['checks']['scheduler'] = {'status': 'error', 'message': 'Scheduler not running'}
        except Exception as e:
            health['status'] = 'degraded'
            health['checks']['scheduler'] = {'status': 'error', 'message': str(e)}

        # Check at least one Docker host is reachable
        try:
            clients = docker_manager.get_all_clients()
            if clients:
                health['checks']['docker'] = {'status': 'ok', 'hosts_connected': len(clients)}
            else:
                health['status'] = 'degraded'
                health['checks']['docker'] = {'status': 'warning', 'message': 'No Docker hosts connected'}
        except Exception as e:
            health['status'] = 'degraded'
            health['checks']['docker'] = {'status': 'error', 'message': str(e)}

        status_code = 200 if health['status'] == 'healthy' else 503 if health['status'] == 'unhealthy' else 200
        return jsonify(health), status_code

    @blueprint.route('/api/version')
    def get_version():
        """Get application version and build info."""
        import sys

        try:
            active_schedules, active_hosts = stats_repo.get_active_counts()
        except Exception:
            active_schedules = 0
            active_hosts = 0

        return jsonify({
            'version': version,
            'python_version': sys.version.split()[0],
            'api_version': 'v1',
            'active_schedules': active_schedules,
            'active_hosts': active_hosts,
        })

    return blueprint
