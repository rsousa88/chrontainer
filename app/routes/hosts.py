from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required


def create_hosts_blueprint(
    *,
    api_key_or_login_required,
    docker_manager,
    host_metrics_repo,
    host_repo,
    host_metrics_service,
    sanitize_string,
    schedule_repo,
    validate_color,
    validate_host_id,
    validate_required_fields,
    validate_url,
    host_default_color: str,
    datetime_factory,
    sqlite3_module,
    logger,
):
    """Create hosts routes with injected dependencies."""
    blueprint = Blueprint('hosts', __name__)

    @blueprint.route('/api/hosts/<int:host_id>/metrics', methods=['GET'])
    @api_key_or_login_required
    def get_host_metrics(host_id: int):
        """Get system metrics for a Docker host."""
        try:
            stats = host_metrics_service.fetch_host_metrics(host_id)
            return jsonify(stats)
        except RuntimeError as e:
            logger.error(f"Failed to get host metrics for {host_id}: {e}")
            return jsonify({'error': str(e)}), 503
        except Exception as e:
            logger.error(f"Failed to get host metrics for {host_id}: {e}")
            return jsonify({'error': str(e)}), 500

    @blueprint.route('/api/hosts/metrics', methods=['GET'])
    @api_key_or_login_required
    def get_all_host_metrics():
        """Get metrics for all enabled hosts."""
        results = []

        hosts = host_metrics_repo.list_enabled_hosts()

        for host_id, host_name in hosts:
            try:
                docker_client = docker_manager.get_client(host_id)
                if not docker_client:
                    results.append({
                        'host_id': host_id,
                        'name': host_name,
                        'status': 'offline',
                        'error': 'Cannot connect',
                    })
                    continue

                info = docker_client.info()

                results.append({
                    'host_id': host_id,
                    'name': host_name,
                    'status': 'online',
                    'os': info.get('OperatingSystem', 'Unknown'),
                    'cpus': info.get('NCPU', 0),
                    'memory_gb': round(info.get('MemTotal', 0) / (1024**3), 2),
                    'containers_running': info.get('ContainersRunning', 0),
                    'containers_total': info.get('Containers', 0),
                    'images': info.get('Images', 0),
                })
            except Exception as e:
                results.append({
                    'host_id': host_id,
                    'name': host_name,
                    'status': 'error',
                    'error': str(e),
                })

        return jsonify(results)

    @blueprint.route('/api/hosts', methods=['GET'])
    @api_key_or_login_required
    def list_hosts():
        """Get all Docker hosts."""
        try:
            host_list = [
                {
                    'id': host[0],
                    'name': host[1],
                    'url': host[2],
                    'enabled': bool(host[3]),
                    'color': host[4],
                    'last_seen': host[5],
                    'created_at': host[6],
                }
                for host in host_repo.list_all()
            ]
            return jsonify(host_list)
        except Exception as e:
            logger.error(f"Failed to get hosts: {e}")
            return jsonify({'error': 'Failed to load Docker hosts. Please check the database connection.'}), 500

    @blueprint.route('/api/hosts', methods=['POST'])
    @login_required
    def add_host():
        """Add a new Docker host."""
        try:
            data = request.json or {}
            name = sanitize_string(data.get('name', ''), max_length=100).strip()
            url = sanitize_string(data.get('url', ''), max_length=500).strip()
            color = sanitize_string(data.get('color', host_default_color), max_length=7).strip()

            if not name or len(name) < 1:
                return jsonify({'error': 'Host name is required'}), 400
            if len(name) > 100:
                return jsonify({'error': 'Host name is too long (max 100 characters)'}), 400

            valid, error = validate_url(url)
            if not valid:
                return jsonify({'error': 'Host URL is required (e.g., tcp://192.168.1.100:2375 or unix:///var/run/docker.sock)'}), 400

            valid, error = validate_color(color)
            if not valid:
                return jsonify({'error': error}), 400

            success, message = docker_manager.test_connection(url)
            if not success:
                return jsonify({'error': f'Connection test failed: {message}. Please ensure the Docker host is running and accessible, and that you have set up a socket-proxy for remote hosts.'}), 400

            host_id = host_repo.create(name, url, color, datetime_factory())

            logger.info(f"Added new host: {name} ({url})")
            return jsonify({'success': True, 'host_id': host_id})
        except sqlite3_module.IntegrityError:
            logger.error(f"Duplicate host: {name} or {url}")
            return jsonify({'error': 'A host with this name or URL already exists'}), 400
        except Exception as e:
            logger.error(f"Failed to add host: {e}")
            return jsonify({'error': 'Failed to add Docker host. Please try again.'}), 500

    @blueprint.route('/api/hosts/<int:host_id>', methods=['PUT'])
    @login_required
    def update_host(host_id: int):
        """Update a Docker host."""
        try:
            data = request.json or {}
            name = data.get('name', '').strip()
            url = data.get('url', '').strip()
            color = data.get('color', host_default_color).strip()
            enabled = data.get('enabled', True)

            if not name:
                return jsonify({'error': 'Host name is required'}), 400
            if not url:
                return jsonify({'error': 'Host URL is required'}), 400
            valid, error = validate_color(color)
            if not valid:
                return jsonify({'error': error}), 400

            if host_id == 1 and not enabled:
                return jsonify({'error': 'Cannot disable the local Docker host (ID: 1). This host is required for Chrontainer to function.'}), 400

            current_url = host_repo.get_url(host_id)
            if not current_url:
                return jsonify({'error': f'Host with ID {host_id} not found'}), 404

            if url != current_url:
                success, message = docker_manager.test_connection(url)
                if not success:
                    return jsonify({'error': f'Connection test failed: {message}. Please verify the Docker host URL and network connectivity.'}), 400

            host_repo.update(host_id, name, url, 1 if enabled else 0, color)

            docker_manager.clear_cache(host_id)

            logger.info(f"Updated host {host_id}: {name}")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to update host: {e}")
            return jsonify({'error': 'Failed to update Docker host. Please try again.'}), 500

    @blueprint.route('/api/hosts/<int:host_id>', methods=['DELETE'])
    @login_required
    def delete_host(host_id: int):
        """Delete a Docker host."""
        try:
            if host_id == 1:
                return jsonify({'error': 'Cannot delete the local Docker host (ID: 1). This host is required for Chrontainer to function.'}), 400

            count = schedule_repo.count_by_host(host_id)
            if count > 0:
                return jsonify({'error': f'Cannot delete host with {count} active schedule(s). Please delete or move the schedules first.'}), 400

            host_repo.delete(host_id)

            docker_manager.clear_cache(host_id)

            logger.info(f"Deleted host {host_id}")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to delete host: {e}")
            return jsonify({'error': 'Failed to delete Docker host. Please try again.'}), 500

    @blueprint.route('/api/hosts/<int:host_id>/test', methods=['POST'])
    @login_required
    def test_host_connection(host_id: int):
        """Test connection to a Docker host."""
        try:
            url = host_repo.get_url(host_id)
            if not url:
                return jsonify({'error': 'Host not found'}), 404
            success, message = docker_manager.test_connection(url)

            if success:
                host_repo.update_last_seen(host_id, datetime_factory())
                host_repo.set_enabled(host_id, 1)
            else:
                host_repo.set_enabled(host_id, 0)

            return jsonify({'success': success, 'message': message})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return blueprint
