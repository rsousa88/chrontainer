from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required


def create_api_keys_blueprint(
    *,
    api_key_repo,
    generate_api_key,
    hash_api_key,
    sanitize_string,
    logger,
):
    """Create API key routes with injected dependencies."""
    blueprint = Blueprint('api_keys', __name__)

    @blueprint.route('/api/keys', methods=['GET'])
    @login_required
    def list_api_keys():
        """List all API keys for current user."""
        try:
            keys = api_key_repo.list_for_user(current_user.id)
            return jsonify([{
                'id': k[0],
                'name': k[1],
                'key_prefix': k[2],
                'permissions': k[3],
                'last_used': k[4],
                'expires_at': k[5],
                'created_at': k[6],
            } for k in keys])
        except Exception as e:
            logger.error(f"Failed to list API keys: {e}")
            return jsonify({'error': 'Failed to list keys'}), 500

    @blueprint.route('/api/keys', methods=['POST'])
    @login_required
    def create_api_key():
        """Create a new API key."""
        try:
            data = request.json or {}
            name = sanitize_string(data.get('name', 'Unnamed Key'), max_length=100)
            permissions = data.get('permissions', 'read')
            expires_days = data.get('expires_days')

            if permissions not in ['read', 'write', 'admin']:
                return jsonify({'error': 'Invalid permissions. Use: read, write, or admin'}), 400

            if permissions == 'admin' and current_user.role != 'admin':
                return jsonify({'error': 'Only admins can create admin API keys'}), 403

            full_key = generate_api_key()
            key_hash = hash_api_key(full_key)
            key_prefix = full_key[:14]

            expires_at = None
            if expires_days:
                try:
                    expires_days = int(expires_days)
                    expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
                except (TypeError, ValueError):
                    return jsonify({'error': 'Invalid expires_days value'}), 400

            key_id = api_key_repo.create(
                user_id=current_user.id,
                name=name,
                key_hash=key_hash,
                key_prefix=key_prefix,
                permissions=permissions,
                expires_at=expires_at,
            )

            logger.info(f"API key created: {key_prefix}... for user {current_user.username}")

            return jsonify({
                'id': key_id,
                'name': name,
                'key': full_key,
                'key_prefix': key_prefix,
                'permissions': permissions,
                'expires_at': expires_at,
                'message': 'Save this key now - it will not be shown again!',
            })
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            return jsonify({'error': 'Failed to create key'}), 500

    @blueprint.route('/api/keys/<int:key_id>', methods=['DELETE'])
    @login_required
    def delete_api_key(key_id: int):
        """Delete an API key."""
        try:
            key = api_key_repo.get_for_user(key_id, current_user.id)
            if not key:
                return jsonify({'error': 'Key not found'}), 404

            api_key_repo.delete(key_id, current_user.id)
            logger.info(f"API key deleted: {key[2]}... for user {current_user.username}")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to delete API key: {e}")
            return jsonify({'error': 'Failed to delete key'}), 500

    return blueprint
