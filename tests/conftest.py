"""
Pytest fixtures for Chrontainer tests
"""
import os
import sys
import tempfile
import pytest

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


@pytest.fixture
def app():
    """Create application for testing"""
    # Use a temporary database for tests
    db_fd, db_path = tempfile.mkstemp(suffix='.db')

    # Set environment variables before importing the app
    os.environ['DATABASE_PATH'] = db_path
    os.environ['SECRET_KEY'] = 'test-secret-key-for-testing'
    os.environ['WTF_CSRF_ENABLED'] = 'false'

    # Import here to use the test environment variables
    from main import app as flask_app, init_db

    flask_app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
    })

    # Initialize the test database
    init_db()

    yield flask_app

    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """Create a test client"""
    return app.test_client()


@pytest.fixture
def authenticated_client(app, client):
    """Create an authenticated test client"""
    # Login with default admin credentials
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'admin'
    }, follow_redirects=True)
    return client


@pytest.fixture
def runner(app):
    """Create a CLI test runner"""
    return app.test_cli_runner()
