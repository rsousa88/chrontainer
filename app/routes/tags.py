from __future__ import annotations

from flask import Blueprint, jsonify, request


def create_tags_blueprint(
    *,
    api_key_or_login_required,
    tag_repo,
    csrf=None,
    sanitize_string,
    validate_color,
    host_default_color: str,
    sqlite3_module,
    logger,
):
    """Create tag routes with injected dependencies."""
    blueprint = Blueprint('tags', __name__)
    if csrf is not None:
        csrf.exempt(blueprint)

    @blueprint.route('/api/tags', methods=['GET'])
    @api_key_or_login_required
    def get_tags():
        """Get all tags."""
        try:
            tags = [
                {'id': row[0], 'name': row[1], 'color': row[2]}
                for row in tag_repo.list_all()
            ]
            return jsonify(tags)
        except Exception as e:
            logger.error(f"Failed to get tags: {e}")
            return jsonify({'error': 'Failed to load tags. Please check the database connection.'}), 500

    @blueprint.route('/api/tags', methods=['POST'])
    @api_key_or_login_required
    def create_tag():
        """Create a new tag."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403
        try:
            data = request.json or {}
            name = data.get('name', '').strip()
            color = data.get('color', host_default_color).strip()

            if not name:
                return jsonify({'error': 'Tag name is required'}), 400

            valid, error = validate_color(color)
            if not valid:
                return jsonify({'error': error}), 400

            tag_id = tag_repo.create(name, color)

            return jsonify({'success': True, 'id': tag_id, 'name': name, 'color': color})
        except sqlite3_module.IntegrityError:
            return jsonify({'error': f'A tag named "{name}" already exists'}), 400
        except Exception as e:
            logger.error(f"Failed to create tag: {e}")
            return jsonify({'error': 'Failed to create tag. Please try again.'}), 500

    @blueprint.route('/api/tags/<int:tag_id>', methods=['DELETE'])
    @api_key_or_login_required
    def delete_tag(tag_id):
        """Delete a tag."""
        if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403
        try:
            tag_repo.delete(tag_id)
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to delete tag: {e}")
            return jsonify({'error': 'Failed to delete tag. Please try again.'}), 500

    return blueprint
