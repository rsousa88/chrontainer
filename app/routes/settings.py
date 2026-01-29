from __future__ import annotations

import requests
from pathlib import Path
from flask import Blueprint, jsonify, render_template, request, send_from_directory
from flask_login import login_required


def create_settings_blueprint(
    *,
    get_setting,
    set_setting,
    configure_update_check_schedule,
    notification_service,
    csrf,
    sanitize_string,
    validate_cron_expression,
    validate_url,
    validate_webhook_url,
    logger,
    update_check_cron_default: str,
    version: str,
):
    """Create settings routes with injected dependencies."""
    blueprint = Blueprint('settings', __name__)
    dist_dir = Path(__file__).resolve().parents[3] / 'frontend' / 'dist'

    @blueprint.route('/settings')
    @login_required
    def settings_page():
        """Settings page."""
        if dist_dir.joinpath('index.html').exists():
            return send_from_directory(dist_dir, 'index.html')
        webhook_url = get_setting('discord_webhook_url', '')
        return render_template('settings.html', discord_webhook_url=webhook_url, version=version)

    @blueprint.route('/api/settings', methods=['GET'])
    @login_required
    def get_settings():
        """Get all settings."""
        try:
            webhook_url = get_setting('discord_webhook_url', '')
            return jsonify({
                'discord_webhook_url': webhook_url,
                'discord_username': get_setting('discord_username', ''),
                'discord_avatar_url': get_setting('discord_avatar_url', ''),
                'ntfy_enabled': get_setting('ntfy_enabled', 'false'),
                'ntfy_server': get_setting('ntfy_server', 'https://ntfy.sh'),
                'ntfy_topic': get_setting('ntfy_topic', ''),
                'ntfy_priority': get_setting('ntfy_priority', '3'),
                'ntfy_access_token': get_setting('ntfy_access_token', ''),
                'update_check_enabled': get_setting('update_check_enabled', 'true'),
                'update_check_cron': get_setting('update_check_cron', update_check_cron_default),
            })
        except Exception as e:
            logger.error(f"Failed to get settings: {e}")
            return jsonify({'error': 'Failed to load settings. Please check the database connection.'}), 500

    @blueprint.route('/api/settings/discord', methods=['POST'])
    @login_required
    def update_discord_settings():
        """Update Discord webhook settings."""
        try:
            data = request.json or {}
            webhook_url = sanitize_string(data.get('webhook_url', ''), max_length=2048).strip()
            username = sanitize_string(data.get('username', ''), max_length=100).strip()
            avatar_url = sanitize_string(data.get('avatar_url', ''), max_length=2048).strip()

            valid, error = validate_webhook_url(webhook_url)
            if not valid:
                return jsonify({'error': error}), 400
            if avatar_url:
                valid_avatar, avatar_error = validate_url(avatar_url)
                if not valid_avatar:
                    return jsonify({'error': avatar_error}), 400

            set_setting('discord_webhook_url', webhook_url)
            set_setting('discord_username', username)
            set_setting('discord_avatar_url', avatar_url)
            logger.info("Discord webhook URL updated")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to update Discord settings: {e}")
            return jsonify({'error': 'Failed to save Discord webhook settings. Please try again.'}), 500

    @blueprint.route('/api/settings/ntfy', methods=['POST'])
    @login_required
    def update_ntfy_settings():
        """Update ntfy notification settings."""
        try:
            data = request.json or {}

            ntfy_enabled = data.get('enabled', False)
            ntfy_server = sanitize_string(data.get('server', 'https://ntfy.sh'), max_length=500).strip()
            ntfy_topic = sanitize_string(data.get('topic', ''), max_length=100).strip()
            ntfy_priority = data.get('priority', 3)
            ntfy_access_token = sanitize_string(data.get('access_token', ''), max_length=500).strip()

            if ntfy_enabled and not ntfy_topic:
                return jsonify({'error': 'Topic is required when ntfy is enabled'}), 400

            if not isinstance(ntfy_priority, int) or ntfy_priority < 1 or ntfy_priority > 5:
                return jsonify({'error': 'Priority must be 1-5'}), 400

            if ntfy_server and not ntfy_server.startswith('http'):
                return jsonify({'error': 'Server must be a valid URL'}), 400

            set_setting('ntfy_enabled', 'true' if ntfy_enabled else 'false')
            set_setting('ntfy_server', ntfy_server)
            set_setting('ntfy_topic', ntfy_topic)
            set_setting('ntfy_priority', str(ntfy_priority))
            set_setting('ntfy_access_token', ntfy_access_token)

            logger.info("ntfy settings updated")
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to update ntfy settings: {e}")
            return jsonify({'error': 'Failed to save settings'}), 500

    @blueprint.route('/api/settings/update-check', methods=['POST'])
    @login_required
    def update_update_check_settings():
        """Update automatic update-check settings."""
        try:
            data = request.json or {}
            enabled = bool(data.get('enabled', False))
            cron_expression = sanitize_string(data.get('cron', update_check_cron_default), max_length=50).strip()

            if enabled:
                valid, error = validate_cron_expression(cron_expression)
                if not valid:
                    return jsonify({'error': error}), 400

            set_setting('update_check_enabled', 'true' if enabled else 'false')
            set_setting('update_check_cron', cron_expression or update_check_cron_default)

            configure_update_check_schedule()
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Failed to update update-check settings: {e}")
            return jsonify({'error': 'Failed to save update-check settings'}), 500

    @blueprint.route('/api/settings/ntfy/test', methods=['POST'])
    @login_required
    def test_ntfy():
        """Test ntfy notification."""
        try:
            ntfy_server = get_setting('ntfy_server', 'https://ntfy.sh')
            ntfy_topic = get_setting('ntfy_topic')

            if not ntfy_topic:
                return jsonify({'error': 'ntfy topic not configured'}), 400

            url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"

            response = requests.post(
                url,
                data="This is a test notification from Chrontainer!".encode('utf-8'),
                headers={
                    'Title': 'Chrontainer Test',
                    'Priority': '3',
                    'Tags': 'bell',
                    **(
                        {'Authorization': f"Bearer {get_setting('ntfy_access_token', '').strip()}"}
                        if get_setting('ntfy_access_token', '').strip()
                        else {}
                    ),
                },
                timeout=10,
            )

            if response.status_code in [200, 204]:
                return jsonify({'success': True, 'message': 'Test notification sent'})
            return jsonify({'error': f'Server returned status {response.status_code}'}), 400
        except Exception as e:
            logger.error(f"Failed to test ntfy: {e}")
            return jsonify({'error': str(e)}), 500

    @blueprint.route('/api/settings/discord/test', methods=['POST'])
    @login_required
    def test_discord_webhook():
        """Test Discord webhook."""
        try:
            webhook_url = get_setting('discord_webhook_url')
            if not webhook_url:
                return jsonify({'error': 'No Discord webhook URL configured. Please add a webhook URL in the settings first.'}), 400

            notification_service.send_discord_notification(
                container_name='test-container',
                action='test',
                status='success',
                message='This is a test notification from Chrontainer!',
            )
            return jsonify({'success': True, 'message': 'Test notification sent'})
        except Exception as e:
            logger.error(f"Failed to test Discord webhook: {e}")
            return jsonify({'error': 'Failed to send test notification. Please check your webhook URL and network connection.'}), 500

    csrf.exempt(update_discord_settings)
    csrf.exempt(update_ntfy_settings)
    csrf.exempt(update_update_check_settings)
    csrf.exempt(test_ntfy)
    csrf.exempt(test_discord_webhook)

    return blueprint
