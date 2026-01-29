from __future__ import annotations

from datetime import datetime

import bcrypt
from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.utils.validators import sanitize_string


def create_auth_blueprint(login_repo, user_class, user_repo, limiter, csrf, version: str, logger, bcrypt_module):
    """Create authentication routes with injected dependencies."""
    blueprint = Blueprint('auth', __name__)

    @blueprint.route('/login', methods=['GET', 'POST'])
    @csrf.exempt
    @limiter.limit('10 per minute')
    def login():
        """Login page."""
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        if request.method == 'POST':
            username = sanitize_string(request.form.get('username', ''), max_length=50).strip()
            password = request.form.get('password', '')

            if not username or not password:
                flash('Please enter both username and password', 'error')
                return render_template('login.html', version=version)

            try:
                user_data = login_repo.get_user_for_login(username)

                if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
                    login_repo.update_last_login(user_data[0], datetime.now())

                    user = user_class(id=user_data[0], username=user_data[1], role=user_data[3])
                    login_user(user)
                    logger.info(f"User {username} logged in")

                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('index'))

                flash('Invalid username or password', 'error')
                return render_template('login.html', version=version)

            except Exception as e:
                logger.error(f"Login error: {e}")
                flash('An error occurred during login', 'error')
                return render_template('login.html', version=version)

        return render_template('login.html', version=version)

    @blueprint.route('/api/login', methods=['POST'])
    @limiter.limit('10 per minute')
    def api_login():
        """API login for SPA clients."""
        if current_user.is_authenticated:
            return jsonify({'success': True, 'username': current_user.username})

        username = sanitize_string(request.form.get('username', ''), max_length=50).strip()
        password = request.form.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        try:
            user_data = login_repo.get_user_for_login(username)

            if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
                login_repo.update_last_login(user_data[0], datetime.now())

                user = user_class(id=user_data[0], username=user_data[1], role=user_data[3])
                login_user(user)
                logger.info(f"User {username} logged in via API")
                return jsonify({'success': True, 'username': user.username})

            return jsonify({'error': 'Invalid username or password'}), 401

        except Exception as e:
            logger.error(f"API login error: {e}")
            return jsonify({'error': 'Login failed'}), 500

    csrf.exempt(api_login)

    @blueprint.route('/logout')
    @login_required
    def logout():
        """Logout."""
        username = current_user.username
        logout_user()
        logger.info(f"User {username} logged out")
        flash('You have been logged out', 'success')
        return redirect(url_for('auth.login'))

    @blueprint.route('/api/logout', methods=['POST'])
    def api_logout():
        """API logout for SPA clients."""
        if not current_user.is_authenticated:
            return jsonify({'success': True})
        username = current_user.username
        logout_user()
        logger.info(f"User {username} logged out via API")
        return jsonify({'success': True})

    csrf.exempt(api_logout)

    @blueprint.route('/user-settings')
    @login_required
    def user_settings_page():
        """Redirect to unified settings page (account tab)."""
        return redirect('/settings#account')

    @blueprint.route('/api/user/change-password', methods=['POST'])
    @login_required
    def change_password():
        """Change current user's password."""
        try:
            data = request.json or {}
            current_password = data.get('current_password', '')
            new_password = data.get('new_password', '')
            confirm_password = data.get('confirm_password', '')

            if not current_password or not new_password or not confirm_password:
                return jsonify({'error': 'All fields are required'}), 400

            if new_password != confirm_password:
                return jsonify({'error': 'New passwords do not match'}), 400

            if len(new_password) < 6:
                return jsonify({'error': 'New password must be at least 6 characters'}), 400

            password_hash = user_repo.get_password_hash(current_user.id)
            if not password_hash:
                return jsonify({'error': 'User not found'}), 404

            if not bcrypt_module.checkpw(current_password.encode('utf-8'), password_hash.encode('utf-8')):
                return jsonify({'error': 'Current password is incorrect'}), 400

            new_hash = bcrypt_module.hashpw(new_password.encode('utf-8'), bcrypt_module.gensalt())
            user_repo.update_password(current_user.id, new_hash.decode('utf-8'))

            logger.info(f"User {current_user.username} changed their password")
            return jsonify({'success': True, 'message': 'Password changed successfully'})

        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return jsonify({'error': 'Failed to change password'}), 500

    return blueprint
