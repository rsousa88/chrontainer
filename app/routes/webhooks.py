from __future__ import annotations

import secrets
import threading

import docker
from flask import Blueprint, jsonify, request
from flask_login import login_required


def create_webhooks_blueprint(
    *,
    webhook_repo,
    docker_manager,
    limiter,
    restart_container,
    start_container,
    stop_container,
    pause_container,
    unpause_container,
    update_container,
    sanitize_string,
    logger,
):
    """Create webhook routes with injected dependencies."""
    blueprint = Blueprint('webhooks', __name__)

    @blueprint.route('/webhook/<token>', methods=['POST', 'GET'])
    @limiter.limit("30 per minute")
    def trigger_webhook(token):
        """Trigger a webhook action - no auth required, uses token."""
        try:
            webhook = webhook_repo.get_by_token(token)

            if not webhook:
                return jsonify({'error': 'Invalid webhook'}), 404

            webhook_id, name, container_id, host_id, action, enabled, locked = webhook

            if not enabled:
                return jsonify({'error': 'Webhook is disabled'}), 403

            override_container = None
            override_host = None

            # Only allow overrides if webhook is not locked
            if not locked:
                if request.method == 'POST' and request.is_json:
                    data = request.json or {}
                    override_container = data.get('container_id')
                    override_host = data.get('host_id')
                else:
                    override_container = request.args.get('container_id')
                    override_host = request.args.get('host_id')

            target_container = override_container or container_id
            target_host = int(override_host or host_id or 1)

            if not target_container:
                return jsonify({'error': 'No container specified'}), 400

            docker_client = docker_manager.get_client(target_host)
            if not docker_client:
                return jsonify({'error': 'Docker host not available'}), 503

            try:
                container = docker_client.containers.get(target_container)
                container_name = container.name
            except docker.errors.NotFound:
                return jsonify({'error': 'Container not found'}), 404

            webhook_repo.record_trigger(webhook_id)

            action_map = {
                'restart': restart_container,
                'start': start_container,
                'stop': stop_container,
                'pause': pause_container,
                'unpause': unpause_container,
                'update': update_container,
            }

            action_func = action_map.get(action)
            if not action_func:
                return jsonify({'error': f'Unknown action: {action}'}), 400

            thread = threading.Thread(
                target=action_func,
                args=[target_container, container_name, None, target_host],
            )
            thread.start()

            logger.info(f"Webhook '{name}' triggered: {action} on {container_name}")

            return jsonify({
                'success': True,
                'webhook': name,
                'action': action,
                'container': container_name,
                'message': f'{action.capitalize()} triggered for {container_name}',
            })

        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return jsonify({'error': 'Webhook execution failed'}), 500

    @blueprint.route('/api/webhooks', methods=['GET'])
    @login_required
    def list_webhooks():
        """List all webhooks."""
        try:
            webhooks = webhook_repo.list_all()

            return jsonify([{
                'id': w[0],
                'name': w[1],
                'token': w[2],
                'container_id': w[3],
                'host_id': w[4],
                'action': w[5],
                'enabled': bool(w[6]),
                'locked': bool(w[7]),
                'last_triggered': w[8],
                'trigger_count': w[9],
                'created_at': w[10],
                'host_name': w[11],
            } for w in webhooks])
        except Exception as e:
            logger.error(f"Failed to list webhooks: {e}")
            return jsonify({'error': 'Failed to list webhooks'}), 500

    @blueprint.route('/api/webhooks', methods=['POST'])
    @login_required
    def create_webhook():
        """Create a new webhook."""
        try:
            data = request.json or {}
            name = sanitize_string(data.get('name', ''), max_length=100)
            container_id = sanitize_string(data.get('container_id', ''), max_length=64) or None
            host_id = data.get('host_id')
            action = sanitize_string(data.get('action', 'restart'), max_length=20)
            locked = 1 if data.get('locked') else 0

            if not name:
                return jsonify({'error': 'Name is required'}), 400

            if action not in ['restart', 'start', 'stop', 'pause', 'unpause', 'update']:
                return jsonify({'error': 'Invalid action'}), 400

            token = secrets.token_urlsafe(24)

            webhook_id = webhook_repo.create(name, token, container_id, host_id, action, locked)

            webhook_url = f"{request.host_url}webhook/{token}"

            logger.info(f"Webhook created: {name}")

            return jsonify({
                'id': webhook_id,
                'name': name,
                'token': token,
                'url': webhook_url,
                'action': action,
                'locked': bool(locked),
            })
        except Exception as e:
            logger.error(f"Failed to create webhook: {e}")
            return jsonify({'error': 'Failed to create webhook'}), 500

    @blueprint.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
    @login_required
    def delete_webhook(webhook_id):
        """Delete a webhook."""
        try:
            webhook_repo.delete(webhook_id)

            logger.info(f"Webhook {webhook_id} deleted")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to delete webhook: {e}")
            return jsonify({'error': 'Failed to delete webhook'}), 500

    @blueprint.route('/api/webhooks/<int:webhook_id>/toggle', methods=['POST'])
    @login_required
    def toggle_webhook(webhook_id):
        """Enable/disable a webhook."""
        try:
            enabled = webhook_repo.toggle_enabled(webhook_id)
            return jsonify({'success': True, 'enabled': bool(enabled)})
        except Exception as e:
            logger.error(f"Failed to toggle webhook: {e}")
            return jsonify({'error': 'Failed to toggle webhook'}), 500

    @blueprint.route('/api/webhooks/<int:webhook_id>/lock', methods=['POST'])
    @login_required
    def toggle_webhook_lock(webhook_id):
        """Toggle lock status for a webhook (locked webhooks ignore container/host overrides)."""
        try:
            locked = webhook_repo.toggle_locked(webhook_id)
            return jsonify({'success': True, 'locked': bool(locked)})
        except Exception as e:
            logger.error(f"Failed to toggle webhook lock: {e}")
            return jsonify({'error': 'Failed to toggle webhook lock'}), 500

    @blueprint.route('/api/webhooks/<int:webhook_id>/regenerate', methods=['POST'])
    @login_required
    def regenerate_webhook_token(webhook_id):
        """Regenerate the token for a webhook."""
        try:
            new_token = secrets.token_urlsafe(24)
            updated = webhook_repo.update_token(webhook_id, new_token)
            if updated == 0:
                return jsonify({'error': 'Webhook not found'}), 404

            webhook_url = f"{request.host_url}webhook/{new_token}"
            logger.info(f"Webhook {webhook_id} token regenerated")

            return jsonify({
                'success': True,
                'token': new_token,
                'url': webhook_url,
            })
        except Exception as e:
            logger.error(f"Failed to regenerate webhook token: {e}")
            return jsonify({'error': 'Failed to regenerate token'}), 500

    return blueprint
