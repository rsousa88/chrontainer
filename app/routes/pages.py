from __future__ import annotations

from pathlib import Path
from flask import Blueprint, redirect, render_template, request, send_from_directory
from flask_login import login_required


def create_pages_blueprint(*, version: str):
    """Create simple page routes."""
    blueprint = Blueprint('pages', __name__)
    dist_dir = Path(__file__).resolve().parents[3] / 'frontend' / 'dist'

    @blueprint.route('/metrics')
    @login_required
    def metrics_page():
        """Host metrics dashboard page."""
        if dist_dir.joinpath('index.html').exists():
            return send_from_directory(dist_dir, 'index.html')
        dark_mode = request.cookies.get('darkMode', 'false') == 'true'
        return render_template('metrics.html', dark_mode=dark_mode)

    @blueprint.route('/hosts')
    @login_required
    def hosts_page():
        """Redirect to unified settings page (hosts tab)."""
        if dist_dir.joinpath('index.html').exists():
            return send_from_directory(dist_dir, 'index.html')
        return redirect('/settings#hosts')

    return blueprint
