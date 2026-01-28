from __future__ import annotations

from flask import Blueprint, redirect, render_template, request
from flask_login import login_required


def create_pages_blueprint(*, version: str):
    """Create simple page routes."""
    blueprint = Blueprint('pages', __name__)

    @blueprint.route('/metrics')
    @login_required
    def metrics_page():
        """Host metrics dashboard page."""
        dark_mode = request.cookies.get('darkMode', 'false') == 'true'
        return render_template('metrics.html', dark_mode=dark_mode)

    @blueprint.route('/hosts')
    @login_required
    def hosts_page():
        """Redirect to unified settings page (hosts tab)."""
        return redirect('/settings#hosts')

    return blueprint
