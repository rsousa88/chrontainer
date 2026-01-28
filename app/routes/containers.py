from __future__ import annotations

import concurrent.futures
import docker
from datetime import datetime
from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required


def create_containers_blueprint(
    *,
    api_key_or_login_required,
    docker_manager,
    fetch_all_containers,
    get_cached_container_stats,
    set_cached_container_stats,
    logger,
    container_service,
    update_service,
    validate_container_id,
    validate_container_name,
    validate_host_id,
    sanitize_string,
    container_tag_repo,
    webui_url_repo,
    schedule_view_repo,
    version: str,
):
    """Create container-related routes with injected dependencies."""
    blueprint = Blueprint('containers', __name__)

    @blueprint.route('/')
    @login_required
    def index():
        """Main dashboard."""
        try:
            container_list = fetch_all_containers()
            schedules = schedule_view_repo.list_with_host_names()
            return render_template('index.html', containers=container_list, schedules=schedules, version=version)
        except Exception as e:
            logger.error(f"Error loading dashboard: {e}")
            return render_template('error.html', error=str(e))

    @blueprint.route('/api/containers')
    @api_key_or_login_required
    def get_containers():
        """API endpoint to get all containers."""
        try:
            container_list = fetch_all_containers()
            return jsonify(container_list)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @blueprint.route('/api/container/<container_id>/restart', methods=['POST'])
    @api_key_or_login_required
    def api_restart_container(container_id):
        """API endpoint to restart a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = data.get('name', 'unknown')
        host_id = data.get('host_id', 1)

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.restart_container(container_id, container_name, host_id=host_id)
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/start', methods=['POST'])
    @api_key_or_login_required
    def api_start_container(container_id):
        """API endpoint to start a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = data.get('name', 'unknown')
        host_id = data.get('host_id', 1)

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.start_container(container_id, container_name, host_id=host_id)
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/stop', methods=['POST'])
    @api_key_or_login_required
    def api_stop_container(container_id):
        """API endpoint to stop a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = data.get('name', 'unknown')
        host_id = data.get('host_id', 1)

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.stop_container(container_id, container_name, host_id=host_id)
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/pause', methods=['POST'])
    @api_key_or_login_required
    def api_pause_container(container_id):
        """API endpoint to pause a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = data.get('name', 'unknown')
        host_id = data.get('host_id', 1)

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.pause_container(container_id, container_name, host_id=host_id)
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/unpause', methods=['POST'])
    @api_key_or_login_required
    def api_unpause_container(container_id):
        """API endpoint to unpause a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = data.get('name', 'unknown')
        host_id = data.get('host_id', 1)

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.unpause_container(container_id, container_name, host_id=host_id)
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/delete', methods=['POST'])
    @api_key_or_login_required
    def api_delete_container(container_id):
        """API endpoint to delete a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = sanitize_string(data.get('name', 'unknown'), max_length=255)
        host_id = data.get('host_id', 1)
        remove_volumes = bool(data.get('remove_volumes', False))
        force = bool(data.get('force', False))

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.delete_container(
            container_id,
            container_name,
            remove_volumes=remove_volumes,
            force=force,
            host_id=host_id,
        )
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/rename', methods=['POST'])
    @api_key_or_login_required
    def api_rename_container(container_id):
        """API endpoint to rename a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = sanitize_string(data.get('name', 'unknown'), max_length=255)
        new_name = sanitize_string(data.get('new_name', ''), max_length=255)
        host_id = data.get('host_id', 1)

        if not new_name:
            return jsonify({'error': 'New name is required'}), 400

        is_valid, error_msg = validate_container_name(new_name)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.rename_container(container_id, container_name, new_name, host_id=host_id)
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/clone', methods=['POST'])
    @api_key_or_login_required
    def api_clone_container(container_id):
        """API endpoint to clone a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = sanitize_string(data.get('name', 'unknown'), max_length=255)
        new_name = sanitize_string(data.get('new_name', ''), max_length=255)
        start_after = bool(data.get('start_after', True))
        host_id = data.get('host_id', 1)

        if not new_name:
            return jsonify({'error': 'New name is required'}), 400

        is_valid, error_msg = validate_container_name(new_name)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        result = container_service.clone_container(
            container_id,
            container_name,
            new_name,
            start_after=start_after,
            host_id=host_id,
        )
        success, message = result.success, result.message
        return jsonify({'success': success, 'message': message})

    @blueprint.route('/api/container/<container_id>/check-update', methods=['GET'])
    def api_check_container_update(container_id):
        """API endpoint to check if a container has an update available."""
        host_id = request.args.get('host_id', 1, type=int)

        try:
            client = docker_manager.get_client(host_id)
            if not client:
                return jsonify({'error': 'Cannot connect to Docker host'}), 500

            container = client.containers.get(container_id)
            has_update, remote_digest, error, note = update_service.check_for_update(container, client)
            payload = {
                'has_update': has_update,
                'remote_digest': remote_digest,
                'error': error,
                'note': note,
                'checked_at': datetime.utcnow().isoformat(),
            }
            update_service.write_update_status(container_id, host_id, payload)

            if error:
                return jsonify({'has_update': False, 'error': error})

            return jsonify({
                'has_update': has_update,
                'remote_digest': remote_digest,
                'note': note,
            })

        except docker.errors.NotFound:
            return jsonify({'error': 'Container not found'}), 404
        except Exception as e:
            logger.error(f"Error checking for update: {e}")
            return jsonify({'error': 'Failed to check for updates'}), 500

    @blueprint.route('/api/containers/check-updates', methods=['GET'])
    @login_required
    def api_check_all_updates():
        """API endpoint to check for updates on all containers."""
        results = []

        try:
            for host_id, host_name, docker_client in docker_manager.get_all_clients():
                try:
                    containers = docker_client.containers.list(all=True)
                    for container in containers:
                        container_id = container.id[:12]
                        try:
                            has_update, remote_digest, error, note = update_service.check_for_update(container, docker_client)
                            payload = {
                                'has_update': has_update,
                                'remote_digest': remote_digest,
                                'error': error,
                                'note': note,
                                'checked_at': datetime.utcnow().isoformat(),
                            }
                            update_service.write_update_status(container_id, host_id, payload)
                            results.append({
                                'container_id': container_id,
                                'container_name': container.name,
                                'host_id': host_id,
                                'host_name': host_name,
                                'has_update': has_update,
                                'error': error,
                                'note': note,
                            })
                        except Exception as e:
                            results.append({
                                'container_id': container_id,
                                'container_name': container.name,
                                'host_id': host_id,
                                'host_name': host_name,
                                'has_update': False,
                                'error': str(e),
                                'note': None,
                            })
                except Exception as e:
                    logger.error(f"Error checking updates for host {host_name}: {e}")

            return jsonify({
                'success': True,
                'results': results,
                'total': len(results),
                'updates_available': sum(1 for r in results if r.get('has_update')),
            })
        except Exception as e:
            logger.error(f"Error in bulk update check: {e}")
            return jsonify({'error': 'Failed to check for updates'}), 500

    @blueprint.route('/api/container/<container_id>/update', methods=['POST'])
    @api_key_or_login_required
    def api_update_container(container_id):
        """API endpoint to update a container."""
        is_valid, error_msg = validate_container_id(container_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        container_name = data.get('name', 'unknown')
        host_id = data.get('host_id', 1)

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        try:
            result = container_service.update_container(container_id, container_name, host_id=host_id)
            success, message = result.success, result.message
            return jsonify({'success': success, 'message': message})

        except Exception as e:
            logger.error(f"Error updating container: {e}")
            return jsonify({'success': False, 'message': f'Update failed: {str(e)}'}), 500

    @blueprint.route('/api/container/<container_id>/logs', methods=['GET'])
    def api_get_container_logs(container_id):
        """API endpoint to get container logs."""
        host_id = request.args.get('host_id', 1, type=int)
        tail = request.args.get('tail', 100, type=int)
        timestamps = request.args.get('timestamps', 'true').lower() == 'true'

        try:
            docker_client = docker_manager.get_client(host_id)
            if not docker_client:
                return jsonify({'error': f'Cannot connect to Docker host (ID: {host_id}). Please check the host connection in Settings > Hosts.'}), 500

            container = docker_client.containers.get(container_id)
            logs = container.logs(
                tail=tail,
                timestamps=timestamps,
                stdout=True,
                stderr=True,
            ).decode('utf-8')

            return jsonify({
                'success': True,
                'logs': logs,
                'container_id': container_id,
                'container_name': container.name,
            })
        except docker.errors.NotFound:
            logger.error(f"Container {container_id} not found on host {host_id}")
            return jsonify({'error': 'Container not found. It may have been removed.'}), 404
        except docker.errors.APIError as e:
            logger.error(f"Docker API error getting logs for {container_id}: {e}")
            return jsonify({'error': 'Failed to retrieve container logs. The container may not be running or accessible.'}), 500
        except Exception as e:
            logger.error(f"Failed to get logs for container {container_id}: {e}")
            return jsonify({'error': 'Failed to retrieve container logs. Please try again.'}), 500

    @blueprint.route('/api/container/<container_id>/stats', methods=['GET'])
    @api_key_or_login_required
    def api_get_container_stats(container_id):
        """API endpoint to get container resource stats."""
        host_id = request.args.get('host_id', 1, type=int)

        try:
            cache_key = f"{container_id}_{host_id}"
            cached = get_cached_container_stats(cache_key)
            if cached:
                return jsonify(cached)

            docker_client = docker_manager.get_client(host_id)
            if not docker_client:
                return jsonify({'error': 'Cannot connect to Docker host'}), 500

            container = docker_client.containers.get(container_id)

            if container.status != 'running':
                return jsonify({
                    'cpu_percent': None,
                    'memory_percent': None,
                    'memory_mb': None,
                    'status': container.status,
                })

            stats = container.stats(stream=False)

            cpu_percent = 0.0
            try:
                cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
                system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
                online_cpus = stats['cpu_stats'].get('online_cpus', 1)
                if system_delta > 0:
                    cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
            except (KeyError, ZeroDivisionError):
                cpu_percent = 0.0

            memory_percent = 0.0
            memory_mb = 0.0
            try:
                memory_usage = stats['memory_stats'].get('usage', 0)
                memory_limit = stats['memory_stats'].get('limit', 1)
                cache = stats['memory_stats'].get('stats', {}).get('cache', 0)
                memory_usage = memory_usage - cache
                memory_percent = (memory_usage / memory_limit) * 100
                memory_mb = memory_usage / (1024 * 1024)
            except (KeyError, ZeroDivisionError):
                pass

            payload = {
                'cpu_percent': round(cpu_percent, 1),
                'memory_percent': round(memory_percent, 1),
                'memory_mb': round(memory_mb, 1),
                'status': container.status,
            }
            set_cached_container_stats(cache_key, payload)
            return jsonify(payload)

        except docker.errors.NotFound:
            return jsonify({'error': 'Container not found'}), 404
        except Exception as e:
            logger.error(f"Failed to get stats for container {container_id}: {e}")
            return jsonify({'error': str(e)}), 500

    @blueprint.route('/api/containers/stats', methods=['GET'])
    @api_key_or_login_required
    def api_get_all_container_stats():
        """API endpoint to get stats for all running containers."""
        cached = get_cached_container_stats('all')
        if cached:
            return jsonify(cached)

        results = {}

        for host_id, host_name, docker_client in docker_manager.get_all_clients():
            try:
                containers = docker_client.containers.list(all=False)
                if not containers:
                    continue

                def fetch_stats(container):
                    container_id = container.id[:12]
                    try:
                        stats = container.stats(stream=False)

                        cpu_percent = 0.0
                        try:
                            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
                            system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
                            online_cpus = stats['cpu_stats'].get('online_cpus', 1)
                            if system_delta > 0:
                                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
                        except (KeyError, ZeroDivisionError):
                            pass

                        memory_percent = 0.0
                        memory_mb = 0.0
                        try:
                            memory_usage = stats['memory_stats'].get('usage', 0)
                            memory_limit = stats['memory_stats'].get('limit', 1)
                            cache = stats['memory_stats'].get('stats', {}).get('cache', 0)
                            memory_usage = memory_usage - cache
                            memory_percent = (memory_usage / memory_limit) * 100
                            memory_mb = memory_usage / (1024 * 1024)
                        except (KeyError, ZeroDivisionError):
                            pass

                        return container_id, {
                            'cpu_percent': round(cpu_percent, 1),
                            'memory_percent': round(memory_percent, 1),
                            'memory_mb': round(memory_mb, 1),
                        }
                    except Exception as e:
                        logger.debug(f"Failed to get stats for {container.name}: {e}")
                        return container_id, None

                max_workers = min(8, len(containers))
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [executor.submit(fetch_stats, container) for container in containers]
                    try:
                        for future in concurrent.futures.as_completed(futures, timeout=6):
                            container_id, stats = future.result()
                            if stats is not None:
                                results[f"{container_id}_{host_id}"] = stats
                    except concurrent.futures.TimeoutError:
                        pass
            except Exception as e:
                logger.error(f"Failed to get containers from host {host_name}: {e}")

        set_cached_container_stats('all', results)
        return jsonify(results)

    @blueprint.route('/api/containers/<container_id>/<int:host_id>/tags', methods=['GET'])
    @api_key_or_login_required
    def get_container_tags(container_id, host_id):
        """Get tags for a specific container."""
        try:
            tags = [
                {'id': row[0], 'name': row[1], 'color': row[2]}
                for row in container_tag_repo.list_for_container(container_id, host_id)
            ]
            return jsonify(tags)
        except Exception as e:
            logger.error(f"Failed to get container tags: {e}")
            return jsonify({'error': 'Failed to load container tags.'}), 500

    @blueprint.route('/api/containers/<container_id>/<int:host_id>/tags', methods=['POST'])
    @api_key_or_login_required
    def add_container_tag(container_id, host_id):
        """Add a tag to a container."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403
        try:
            data = request.json or {}
            tag_id = data.get('tag_id')

            if not tag_id:
                return jsonify({'error': 'Tag ID is required. Please select a tag to add.'}), 400

            container_tag_repo.add(container_id, host_id, tag_id)
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to add container tag: {e}")
            return jsonify({'error': 'Failed to add tag to container. Please try again.'}), 500

    @blueprint.route('/api/containers/<container_id>/<int:host_id>/tags/<int:tag_id>', methods=['DELETE'])
    @api_key_or_login_required
    def remove_container_tag(container_id, host_id, tag_id):
        """Remove a tag from a container."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403
        try:
            container_tag_repo.remove(container_id, host_id, tag_id)
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to remove container tag: {e}")
            return jsonify({'error': 'Failed to remove tag from container. Please try again.'}), 500

    @blueprint.route('/api/containers/<container_id>/<int:host_id>/webui', methods=['GET'])
    @login_required
    def get_container_webui(container_id, host_id):
        """Get Web UI URL for a container."""
        try:
            url = webui_url_repo.get(container_id, host_id)
            return jsonify({'url': url})
        except Exception as e:
            logger.error(f"Failed to get container Web UI URL: {e}")
            return jsonify({'error': 'Failed to load Web UI URL.'}), 500

    @blueprint.route('/api/containers/<container_id>/<int:host_id>/webui', methods=['POST'])
    @login_required
    def set_container_webui(container_id, host_id):
        """Set Web UI URL for a container."""
        try:
            data = request.json or {}
            url = data.get('url', '').strip()
            if url:
                webui_url_repo.upsert(container_id, host_id, url)
            else:
                webui_url_repo.delete(container_id, host_id)
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to set container Web UI URL: {e}")
            return jsonify({'error': 'Failed to save Web UI URL. Please try again.'}), 500

    return blueprint
