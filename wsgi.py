"""
WSGI entry point for Chrontainer
Use this with production WSGI servers like Gunicorn or uWSGI
"""
import os
import sys

# Add app directory to path
sys.path.insert(0, os.path.dirname(__file__))

from app.main import app, init_db, load_schedules, update_service

# Initialize database and schedules on startup
if __name__ != '__main__':
    # Only initialize when running under WSGI server, not when imported
    try:
        init_db()
        load_schedules()
        update_service.configure_update_check_schedule()
    except Exception as e:
        print(f"Error during initialization: {e}", file=sys.stderr)
        raise

# WSGI application
application = app

if __name__ == '__main__':
    # For development/testing only
    # In production, use: gunicorn -c gunicorn.conf.py wsgi:application
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
