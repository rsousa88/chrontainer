from __future__ import annotations

from pathlib import Path
from flask import Blueprint, jsonify, render_template, request, send_from_directory
from flask_login import login_required


def create_images_blueprint(
    *,
    api_key_or_login_required,
    clear_image_usage_cache,
    fetch_all_images,
    docker_manager,
    csrf=None,
    sanitize_string,
    validate_host_id,
    logger,
    logs_repo=None,
    version: str,
):
    """Create image routes with injected dependencies."""
    blueprint = Blueprint('images', __name__)
    if csrf is not None:
        csrf.exempt(blueprint)
    dist_dir = Path(__file__).resolve().parents[3] / 'frontend' / 'dist'

    @blueprint.route('/images')
    @login_required
    def images_page():
        """Image management page."""
        if dist_dir.joinpath('index.html').exists():
            return send_from_directory(dist_dir, 'index.html')
        return render_template('images.html', version=version)

    @blueprint.route('/api/images', methods=['GET'])
    @api_key_or_login_required
    def list_images():
        """List all images across all Docker hosts."""
        try:
            refresh = request.args.get('refresh', '0') == '1'
            host_id = request.args.get('host_id', type=int)
            if refresh:
                clear_image_usage_cache()
            images = fetch_all_images(host_id)
            return jsonify(images)
        except Exception as e:
            logger.error(f"Failed to list images: {e}")
            return jsonify({'error': 'Failed to list images'}), 500

    @blueprint.route('/api/images/pull', methods=['POST'])
    @api_key_or_login_required
    def pull_image():
        """Pull a Docker image."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        image_ref = sanitize_string(data.get('image', ''), max_length=255).strip()
        host_id = data.get('host_id', 1)

        if not image_ref:
            return jsonify({'error': 'Image reference is required'}), 400

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        try:
            client = docker_manager.get_client(host_id)
            if not client:
                return jsonify({'error': 'Cannot connect to Docker host'}), 500

            client.images.pull(image_ref)
            if logs_repo:
                logs_repo.insert_action_log(None, image_ref, 'image_pull', 'success', f'Pulled {image_ref}', host_id)
            return jsonify({'success': True, 'message': f'Pulled {image_ref} successfully'})
        except Exception as e:
            logger.error(f"Failed to pull image {image_ref} on host {host_id}: {e}")
            if logs_repo:
                logs_repo.insert_action_log(None, image_ref, 'image_pull', 'error', str(e), host_id)
            return jsonify({'error': 'Failed to pull image'}), 500

    @blueprint.route('/api/images/<image_id>', methods=['DELETE'])
    @api_key_or_login_required
    def delete_image(image_id):
        """Delete a Docker image."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        host_id = request.args.get('host_id', 1, type=int)
        force = bool((request.json or {}).get('force', False))
        image_id = sanitize_string(image_id, max_length=200).strip()

        if not image_id:
            return jsonify({'error': 'Image ID is required'}), 400

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        try:
            client = docker_manager.get_client(host_id)
            if not client:
                return jsonify({'error': 'Cannot connect to Docker host'}), 500

            client.images.remove(image_id, force=force)
            if logs_repo:
                logs_repo.insert_action_log(None, image_id, 'image_delete', 'success', 'Image removed', host_id)
            return jsonify({'success': True, 'message': 'Image removed'})
        except Exception as e:
            logger.error(f"Failed to delete image {image_id} on host {host_id}: {e}")
            if logs_repo:
                logs_repo.insert_action_log(None, image_id, 'image_delete', 'error', str(e), host_id)
            return jsonify({'error': 'Failed to delete image'}), 500

    @blueprint.route('/api/images/prune', methods=['POST'])
    @api_key_or_login_required
    def prune_images():
        """Prune unused images."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

        data = request.json or {}
        host_id = data.get('host_id', 1)
        dangling_only = data.get('dangling_only', False)

        is_valid, error_msg = validate_host_id(host_id)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        try:
            client = docker_manager.get_client(host_id)
            if not client:
                return jsonify({'error': 'Cannot connect to Docker host. Check the host URL and socket availability.'}), 400

            if dangling_only:
                filters = {'dangling': ['true']}
            else:
                filters = {'dangling': ['false']}
            result = client.images.prune(filters=filters)
            if logs_repo:
                reclaimed = result.get('SpaceReclaimed', 0)
                logs_repo.insert_action_log(None, 'images', 'image_prune', 'success', f'Reclaimed {reclaimed} bytes', host_id)
            return jsonify({
                'success': True,
                'reclaimed': result.get('SpaceReclaimed', 0),
                'images_deleted': result.get('ImagesDeleted', []) or [],
            })
        except Exception as e:
            logger.error(f"Failed to prune images on host {host_id}: {e}")
            if logs_repo:
                logs_repo.insert_action_log(None, 'images', 'image_prune', 'error', str(e), host_id)
            return jsonify({'error': 'Failed to prune images'}), 500

    return blueprint
