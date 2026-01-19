"""
Chrontainer - Docker Container Scheduler
Main Flask application
"""
import os
import docker
import sqlite3
import bcrypt
import secrets
import hashlib
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timedelta
import logging
from functools import wraps
from dotenv import load_dotenv
import re

# Load environment variables
load_dotenv()

# Version
VERSION = "0.4.0"

# Helper function to generate image registry and documentation links
def get_image_links(image_name):
    """Generate registry, GitHub, and docs links from image name"""
    links = {'registry': None, 'github': None, 'docs': None}

    if not image_name or image_name == 'unknown':
        return links

    try:
        # Parse image name (registry/namespace/repo:tag or namespace/repo:tag or repo:tag)
        parts = image_name.split('/')
        tag_split = parts[-1].split(':')
        repo = tag_split[0]

        # Determine registry and namespace
        if len(parts) >= 3:  # registry/namespace/repo
            registry = parts[0]
            namespace = parts[1]
        elif len(parts) == 2:  # namespace/repo (Docker Hub default)
            registry = 'docker.io'
            namespace = parts[0]
        else:  # repo only (official Docker Hub image)
            registry = 'docker.io'
            namespace = 'library'

        # Generate registry link
        if registry == 'docker.io':
            if namespace == 'library':
                links['registry'] = f'https://hub.docker.com/_/{repo}'
            else:
                links['registry'] = f'https://hub.docker.com/r/{namespace}/{repo}'
        elif registry == 'ghcr.io':
            links['registry'] = f'https://github.com/{namespace}/{repo}/pkgs/container/{repo}'
        elif registry == 'gcr.io':
            links['registry'] = f'https://gcr.io/{namespace}/{repo}'

        # Generate GitHub link for known publishers
        linuxserver_images = ['plex', 'sonarr', 'radarr', 'jellyfin', 'homeassistant', 'nginx', 'swag']
        if namespace == 'linuxserver':
            links['github'] = f'https://github.com/linuxserver/docker-{repo}'
            links['docs'] = f'https://docs.linuxserver.io/images/docker-{repo}'
        elif namespace in ['jellyfin', 'homeassistant', 'grafana', 'prom']:
            links['github'] = f'https://github.com/{namespace}/{repo}'
        elif registry == 'ghcr.io':
            links['github'] = f'https://github.com/{namespace}/{repo}'

    except Exception as e:
        logger.debug(f"Failed to parse image name {image_name}: {e}")

    return links

VERSION_LABEL_KEYS = (
    'org.opencontainers.image.version',
    'org.label-schema.version',
    'version'
)
NON_VERSION_TAGS = {
    'latest', 'stable', 'edge', 'nightly', 'main', 'master', 'dev', 'develop'
}
VERSION_TAG_RE = re.compile(r'^v?\d+(?:\.\d+)+(?:[-._][0-9A-Za-z]+)*$')
VERSION_IN_TEXT_RE = re.compile(r'v?\d+(?:\.\d+)+(?:[-._][0-9A-Za-z]+)*')
HOST_DEFAULT_COLOR = '#e8f4f8'

def validate_color(color):
    if not color:
        return False, 'Color is required'
    if not re.match(r'^#[0-9a-fA-F]{6}$', color):
        return False, 'Color must be a hex value like #1ea7e1'
    return True, None

def get_contrast_text_color(color, default='#2c3e50'):
    if not color or not re.match(r'^#[0-9a-fA-F]{6}$', color):
        return default
    red = int(color[1:3], 16)
    green = int(color[3:5], 16)
    blue = int(color[5:7], 16)
    luminance = (0.299 * red + 0.587 * green + 0.114 * blue) / 255
    return '#000000' if luminance > 0.6 else '#ffffff'

def strip_image_tag(image_name):
    """Return image name without tag or digest for display."""
    if not image_name:
        return image_name

    base = image_name.split('@', 1)[0]
    parts = base.rsplit('/', 1)
    if len(parts) == 2:
        prefix, last = parts
    else:
        prefix, last = '', parts[0]

    if ':' in last:
        last = last.split(':', 1)[0]

    return f"{prefix}/{last}" if prefix else last

def get_image_version(container, image_name):
    """Best-effort version from image labels, falling back to version-like tags."""
    labels = {}
    try:
        image_labels = container.image.attrs.get('Config', {}).get('Labels', {}) or {}
        container_labels = container.attrs.get('Config', {}).get('Labels', {}) or {}
        labels = {**container_labels, **image_labels}
    except Exception:
        labels = {}

    for key in VERSION_LABEL_KEYS:
        value = labels.get(key)
        if value:
            return value.strip(), 'label'

    ref_name = labels.get('org.opencontainers.image.ref.name', '')
    if ref_name:
        match = VERSION_IN_TEXT_RE.search(ref_name)
        if match:
            return match.group(0), 'label'

    try:
        envs = container.attrs.get('Config', {}).get('Env', []) or []
        for entry in envs:
            if '=' not in entry:
                continue
            key, value = entry.split('=', 1)
            if 'VERSION' not in key.upper():
                continue
            match = VERSION_IN_TEXT_RE.search(value)
            if match:
                return match.group(0), 'env'
    except Exception:
        pass

    tag = None
    if image_name and ':' in image_name:
        tag = image_name.rsplit(':', 1)[1].strip()

    if tag and tag.lower() not in NON_VERSION_TAGS and VERSION_TAG_RE.match(tag):
        return tag, 'tag'

    if tag and tag.lower() not in NON_VERSION_TAGS:
        match = VERSION_IN_TEXT_RE.search(tag)
        if match:
            return match.group(0), 'tag'

    return 'unknown', 'unknown'

def get_registry_version(registry_data):
    """Best-effort version from registry metadata annotations."""
    try:
        descriptor = registry_data.attrs.get('Descriptor', {}) if registry_data else {}
        annotations = descriptor.get('annotations') or descriptor.get('Annotations') or registry_data.attrs.get('Annotations') or {}
        for key in VERSION_LABEL_KEYS:
            value = annotations.get(key)
            if value:
                return value.strip()
    except Exception as e:
        logger.debug(f"Failed to parse registry version: {e}")
    return None

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path configuration
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/data/chrontainer.db')

app = Flask(__name__, template_folder='../templates')

# Security Configuration
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    logger.warning("SECRET_KEY not set! Using insecure default. Generate a secure key with: python -c 'import secrets; print(secrets.token_hex(32))'")
    SECRET_KEY = 'dev-secret-key-change-in-production'

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = os.environ.get('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# CSRF Protection
csrf = CSRFProtect(app)

# Security Headers (Talisman)
# Only enforce HTTPS if explicitly enabled (for reverse proxy setups)
force_https = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
if force_https:
    Talisman(app,
        force_https=True,
        strict_transport_security=True,
        content_security_policy={
            'default-src': "'self'",
            'script-src': ["'self'", "'unsafe-inline'"],  # Allow inline scripts for modals
            'style-src': ["'self'", "'unsafe-inline'"],   # Allow inline styles
            'img-src': ["'self'", "data:", "https:"],     # Allow data URIs and external images
        }
    )
else:
    # Set security headers without forcing HTTPS (for development or reverse proxy)
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

# Rate Limiting
rate_limit_per_minute = os.environ.get('RATE_LIMIT_PER_MINUTE', '60')
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{rate_limit_per_minute} per minute"],
    storage_uri="memory://"
)

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            return User(id=user_data[0], username=user_data[1], role=user_data[2])
        return None
    except Exception as e:
        logger.error(f"Error loading user: {e}")
        return None

# Role-based access control decorator
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('You need administrator privileges to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Input Validation Functions
def validate_container_id(container_id):
    """Validate container ID format (12 or 64 hex chars)"""
    if not container_id:
        return False, "Container ID is required"
    if not re.match(r'^[a-f0-9]{12}$|^[a-f0-9]{64}$', container_id):
        return False, "Invalid container ID format"
    return True, None

def validate_container_name(name):
    """Validate container name (Docker naming rules)"""
    if not name:
        return False, "Container name is required"
    if len(name) > 255:
        return False, "Container name is too long (max 255 characters)"
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$', name):
        return False, "Container name contains invalid characters"
    return True, None

def validate_cron_expression(cron_expr):
    """Validate cron expression format"""
    if not cron_expr:
        return False, "Cron expression is required"
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False, "Invalid cron expression format. Must be 5 fields: minute hour day month day_of_week"
    # Additional validation is done by CronTrigger
    return True, None

def validate_url(url, schemes=['http', 'https']):
    """Validate URL format"""
    if not url:
        return False, "URL is required"
    if len(url) > 2048:
        return False, "URL is too long"
    # Basic URL pattern check
    pattern = r'^(https?|unix|tcp)://[^\s]+'
    if not re.match(pattern, url):
        return False, "Invalid URL format"
    return True, None

def validate_webhook_url(url):
    """Validate Discord webhook URL"""
    if not url:
        return True, None  # Empty is allowed (disables webhook)
    if not url.startswith('https://discord.com/api/webhooks/'):
        return False, "Invalid Discord webhook URL. Must start with https://discord.com/api/webhooks/"
    return validate_url(url)

def sanitize_string(value, max_length=255):
    """Sanitize string input"""
    if not value:
        return ""
    # Remove null bytes and control characters
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(value))
    # Truncate to max length
    return value[:max_length].strip()

def generate_api_key():
    """Generate a new API key"""
    key_body = secrets.token_urlsafe(22)[:30]
    return f"chron_{key_body}"

def hash_api_key(key):
    """Hash an API key for storage"""
    return hashlib.sha256(key.encode()).hexdigest()

def verify_api_key(key, key_hash):
    """Verify an API key against its hash"""
    return hash_api_key(key) == key_hash

def api_key_or_login_required(f):
    """Allow either session auth or API key auth"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key:
            if not api_key.startswith('chron_'):
                return jsonify({'error': 'Invalid API key format'}), 401

            key_hash = hash_api_key(api_key)
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ak.id, ak.user_id, ak.permissions, ak.expires_at, u.role
                FROM api_keys ak
                JOIN users u ON ak.user_id = u.id
                WHERE ak.key_hash = ?
            ''', (key_hash,))
            result = cursor.fetchone()

            if not result:
                conn.close()
                return jsonify({'error': 'Invalid API key'}), 401

            key_id, user_id, permissions, expires_at, user_role = result

            if expires_at:
                try:
                    expires_dt = datetime.fromisoformat(expires_at)
                    if expires_dt < datetime.now():
                        conn.close()
                        return jsonify({'error': 'API key expired'}), 401
                except ValueError:
                    conn.close()
                    return jsonify({'error': 'Invalid API key expiry'}), 401

            cursor.execute('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?', (key_id,))
            conn.commit()
            conn.close()

            request.api_key_auth = True
            request.api_key_permissions = permissions
            request.api_key_user_id = user_id
            request.api_key_user_role = user_role
            return f(*args, **kwargs)

        if current_user.is_authenticated:
            request.api_key_auth = False
            return f(*args, **kwargs)

        return jsonify({'error': 'Authentication required'}), 401

    return decorated_function

# Docker client manager for multi-host support
class DockerHostManager:
    """Manages connections to multiple Docker hosts"""

    def __init__(self):
        self.clients = {}
        self.last_check = {}

    def get_client(self, host_id=1):
        """Get Docker client for a specific host"""
        # Check if we have a cached client
        if host_id in self.clients:
            return self.clients[host_id]

        # Get host info from database
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, url, enabled FROM hosts WHERE id = ?', (host_id,))
            host = cursor.fetchone()
            conn.close()

            if not host or not host[3]:  # Check if host exists and is enabled
                logger.warning(f"Host {host_id} not found or disabled")
                return None

            host_id, host_name, host_url, enabled = host

            # Create Docker client
            client = docker.DockerClient(base_url=host_url)
            client.ping()  # Test connection

            # Cache the client
            self.clients[host_id] = client
            self.last_check[host_id] = datetime.now()

            # Update last_seen in database
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('UPDATE hosts SET last_seen = ? WHERE id = ?', (datetime.now(), host_id))
            conn.commit()
            conn.close()

            logger.info(f"Connected to Docker host: {host_name} ({host_url})")
            return client

        except Exception as e:
            logger.error(f"Failed to connect to host {host_id}: {e}")
            # Remove from cache if connection failed
            if host_id in self.clients:
                del self.clients[host_id]
            return None

    def get_all_clients(self):
        """Get all enabled Docker clients with their host info"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, url FROM hosts WHERE enabled = 1')
            hosts = cursor.fetchall()
            conn.close()

            result = []
            for host_id, host_name, host_url in hosts:
                client = self.get_client(host_id)
                if client:
                    result.append((host_id, host_name, client))
            return result

        except Exception as e:
            logger.error(f"Failed to get all clients: {e}")
            return []

    def test_connection(self, host_url):
        """Test connection to a Docker host"""
        try:
            client = docker.DockerClient(base_url=host_url)
            client.ping()
            return True, "Connection successful"
        except Exception as e:
            return False, str(e)

    def clear_cache(self, host_id=None):
        """Clear cached client(s)"""
        if host_id:
            if host_id in self.clients:
                del self.clients[host_id]
        else:
            self.clients.clear()

# Initialize Docker host manager
docker_manager = DockerHostManager()

# Container update management functions
def check_for_update(container, client):
    """Check if a container has an update available"""
    try:
        # Get the image used by the container
        image_name = container.image.tags[0] if container.image.tags else container.attrs.get('Config', {}).get('Image', '')

        if not image_name or ':' not in image_name:
            return False, None, "Unable to determine image tag"

        # Get local image digest
        local_image = container.image
        local_digest = local_image.attrs.get('RepoDigests', [])
        if not local_digest:
            return False, None, "No local digest available"
        local_digest = local_digest[0].split('@')[1] if '@' in local_digest[0] else None

        # Pull latest image info without actually pulling the image
        repository, tag = image_name.rsplit(':', 1) if ':' in image_name else (image_name, 'latest')

        try:
            # Get registry data for the image
            registry_data = client.images.get_registry_data(image_name)
            remote_digest = registry_data.attrs.get('Descriptor', {}).get('digest')
            remote_version = get_registry_version(registry_data)

            if not remote_digest or not local_digest:
                return False, None, None, "Unable to compare digests"

            # Compare digests
            has_update = (remote_digest != local_digest)
            return has_update, remote_digest, remote_version, None

        except docker.errors.APIError as e:
            # Handle rate limits, authentication errors, etc.
            message = str(e)
            if 'distribution' in message and 'Forbidden' in message:
                return False, None, None, "Registry error: socket-proxy forbids distribution endpoint. Enable DISTRIBUTION=1."
            return False, None, None, f"Registry error: {message}"

    except Exception as e:
        logger.error(f"Error checking for update: {e}")
        return False, None, None, str(e)

def update_container(container_id, container_name, schedule_id=None, host_id=1):
    """Update a container by pulling the latest image and recreating it"""
    try:
        client = docker_manager.get_client(host_id)
        if not client:
            return False, "Cannot connect to Docker host"

        # Get container
        container = client.containers.get(container_id)

        # Get container configuration
        attrs = container.attrs
        image_name = attrs.get('Config', {}).get('Image', '')

        if not image_name:
            return False, "Unable to determine container image"

        # Get container settings for recreation
        config = attrs.get('Config', {})
        host_config = attrs.get('HostConfig', {})
        networking_config = attrs.get('NetworkSettings', {})

        container_settings = {
            'name': container.name,
            'image': image_name,
            'command': config.get('Cmd'),
            'environment': config.get('Env', []),
            'volumes': host_config.get('Binds', []),
            'ports': config.get('ExposedPorts', {}),
            'labels': config.get('Labels', {}),
            'restart_policy': host_config.get('RestartPolicy', {}),
            'network_mode': host_config.get('NetworkMode'),
            'detach': True
        }

        # Stop and remove the old container
        logger.info(f"Stopping container {container_name}...")
        container.stop(timeout=10)
        container.remove()

        # Pull the latest image
        logger.info(f"Pulling latest image {image_name}...")
        client.images.pull(image_name)

        # Create and start new container with same settings
        logger.info(f"Creating new container {container_name}...")
        new_container = client.containers.run(**container_settings)

        message = f"Container {container_name} updated successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'update', 'success', message, host_id)
        send_discord_notification(container_name, 'update', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'update', 'success', message, schedule_id)

        # Update last_run in schedules
        if schedule_id:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE schedules SET last_run = ? WHERE id = ?',
                (datetime.now(), schedule_id)
            )
            conn.commit()
            conn.close()

        return True, message

    except Exception as e:
        message = f"Failed to update container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'update', 'error', message, host_id)
        send_discord_notification(container_name, 'update', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'update', 'error', message, schedule_id)
        return False, message

# Initialize APScheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Database initialization
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Create hosts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            url TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            color TEXT DEFAULT '#e8f4f8',
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create schedules table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL DEFAULT 1,
            container_id TEXT NOT NULL,
            container_name TEXT NOT NULL,
            action TEXT NOT NULL,
            cron_expression TEXT NOT NULL,
            one_time INTEGER DEFAULT 0,
            run_at TIMESTAMP,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_run TIMESTAMP,
            next_run TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        )
    ''')

    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id INTEGER,
            host_id INTEGER,
            container_name TEXT,
            action TEXT,
            status TEXT,
            message TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        )
    ''')

    # Create settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create tags table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            color TEXT DEFAULT '#3498db',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create container_tags table (many-to-many relationship)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS container_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            container_id TEXT NOT NULL,
            host_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts(id),
            FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE,
            UNIQUE(container_id, host_id, tag_id)
        )
    ''')

    # Create container_webui_urls table for manual Web UI URLs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS container_webui_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            container_id TEXT NOT NULL,
            host_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts(id),
            UNIQUE(container_id, host_id)
        )
    ''')

    # Create users table for authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')

    # Create api_keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            permissions TEXT DEFAULT 'read',
            last_used TIMESTAMP,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Create webhooks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            container_id TEXT,
            host_id INTEGER,
            action TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_triggered TIMESTAMP,
            trigger_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create default admin user if no users exist
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]
    if user_count == 0:
        default_password = 'admin'  # CHANGE THIS ON FIRST LOGIN!
        password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        ''', ('admin', password_hash.decode('utf-8'), 'admin'))
        logger.info("Created default admin user (username: admin, password: admin) - PLEASE CHANGE THE PASSWORD!")

    # Migration: Add host_id column to existing schedules if needed
    cursor.execute("PRAGMA table_info(schedules)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'host_id' not in columns:
        logger.info("Migrating schedules table - adding host_id column")
        cursor.execute('ALTER TABLE schedules ADD COLUMN host_id INTEGER NOT NULL DEFAULT 1')
    if 'one_time' not in columns:
        logger.info("Migrating schedules table - adding one_time column")
        cursor.execute('ALTER TABLE schedules ADD COLUMN one_time INTEGER DEFAULT 0')
    if 'run_at' not in columns:
        logger.info("Migrating schedules table - adding run_at column")
        cursor.execute('ALTER TABLE schedules ADD COLUMN run_at TIMESTAMP')

    # Migration: Add host_id column to existing logs if needed
    cursor.execute("PRAGMA table_info(logs)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'host_id' not in columns:
        logger.info("Migrating logs table - adding host_id column")
        cursor.execute('ALTER TABLE logs ADD COLUMN host_id INTEGER DEFAULT 1')

    # Migration: Add color column to hosts if needed
    cursor.execute("PRAGMA table_info(hosts)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'color' not in columns:
        logger.info("Migrating hosts table - adding color column")
        cursor.execute(f"ALTER TABLE hosts ADD COLUMN color TEXT DEFAULT '{HOST_DEFAULT_COLOR}'")
        cursor.execute('UPDATE hosts SET color = ? WHERE color IS NULL OR color = ""', (HOST_DEFAULT_COLOR,))

    # Insert default local host if not exists
    cursor.execute('''
        INSERT OR IGNORE INTO hosts (id, name, url, enabled, color, last_seen)
        VALUES (1, 'Local', 'unix://var/run/docker.sock', 1, ?, ?)
    ''', (HOST_DEFAULT_COLOR, datetime.now()))

    conn.commit()
    conn.close()
    logger.info("Database initialized")

def get_db():
    """Get database connection"""
    return sqlite3.connect(DATABASE_PATH)

def restart_container(container_id, container_name, schedule_id=None, host_id=1):
    """Restart a Docker container"""
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container = docker_client.containers.get(container_id)
        container.restart()
        message = f"Container {container_name} restarted successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'restart', 'success', message, host_id)
        send_discord_notification(container_name, 'restart', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'restart', 'success', message, schedule_id)

        # Update last_run in schedules
        if schedule_id:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE schedules SET last_run = ? WHERE id = ?',
                (datetime.now(), schedule_id)
            )
            conn.commit()
            conn.close()

        return True, message
    except Exception as e:
        message = f"Failed to restart container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'restart', 'error', message, host_id)
        send_discord_notification(container_name, 'restart', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'restart', 'error', message, schedule_id)
        return False, message

def start_container(container_id, container_name, schedule_id=None, host_id=1):
    """Start a Docker container"""
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container = docker_client.containers.get(container_id)
        container.start()
        message = f"Container {container_name} started successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'start', 'success', message, host_id)
        send_discord_notification(container_name, 'start', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'start', 'success', message, schedule_id)

        # Update last_run in schedules
        if schedule_id:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE schedules SET last_run = ? WHERE id = ?',
                (datetime.now(), schedule_id)
            )
            conn.commit()
            conn.close()

        return True, message
    except Exception as e:
        message = f"Failed to start container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'start', 'error', message, host_id)
        send_discord_notification(container_name, 'start', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'start', 'error', message, schedule_id)
        return False, message

def stop_container(container_id, container_name, schedule_id=None, host_id=1):
    """Stop a Docker container"""
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container = docker_client.containers.get(container_id)
        container.stop()
        message = f"Container {container_name} stopped successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'stop', 'success', message, host_id)
        send_discord_notification(container_name, 'stop', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'stop', 'success', message, schedule_id)

        # Update last_run in schedules
        if schedule_id:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE schedules SET last_run = ? WHERE id = ?',
                (datetime.now(), schedule_id)
            )
            conn.commit()
            conn.close()

        return True, message
    except Exception as e:
        message = f"Failed to stop container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'stop', 'error', message, host_id)
        send_discord_notification(container_name, 'stop', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'stop', 'error', message, schedule_id)
        return False, message

def pause_container(container_id, container_name, schedule_id=None, host_id=1):
    """Pause a Docker container"""
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container = docker_client.containers.get(container_id)
        container.pause()
        message = f"Container {container_name} paused successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'pause', 'success', message, host_id)
        send_discord_notification(container_name, 'pause', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'pause', 'success', message, schedule_id)

        # Update last_run in schedules
        if schedule_id:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE schedules SET last_run = ? WHERE id = ?',
                (datetime.now(), schedule_id)
            )
            conn.commit()
            conn.close()

        return True, message
    except Exception as e:
        message = f"Failed to pause container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'pause', 'error', message, host_id)
        send_discord_notification(container_name, 'pause', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'pause', 'error', message, schedule_id)
        return False, message

def unpause_container(container_id, container_name, schedule_id=None, host_id=1):
    """Unpause a Docker container"""
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container = docker_client.containers.get(container_id)
        container.unpause()
        message = f"Container {container_name} unpaused successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'unpause', 'success', message, host_id)
        send_discord_notification(container_name, 'unpause', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'unpause', 'success', message, schedule_id)

        # Update last_run in schedules
        if schedule_id:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE schedules SET last_run = ? WHERE id = ?',
                (datetime.now(), schedule_id)
            )
            conn.commit()
            conn.close()

        return True, message
    except Exception as e:
        message = f"Failed to unpause container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'unpause', 'error', message, host_id)
        send_discord_notification(container_name, 'unpause', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'unpause', 'error', message, schedule_id)
        return False, message

def log_action(schedule_id, container_name, action, status, message, host_id=1):
    """Log an action to the database"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO logs (schedule_id, host_id, container_name, action, status, message) VALUES (?, ?, ?, ?, ?, ?)',
            (schedule_id, host_id, container_name, action, status, message)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log action: {e}")

def get_setting(key, default=None):
    """Get a setting value from the database"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else default
    except Exception as e:
        logger.error(f"Failed to get setting {key}: {e}")
        return default

def set_setting(key, value):
    """Set a setting value in the database"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)',
            (key, value, datetime.now())
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to set setting {key}: {e}")
        return False

def send_discord_notification(container_name, action, status, message, schedule_id=None):
    """Send a Discord webhook notification"""
    webhook_url = get_setting('discord_webhook_url')
    if not webhook_url:
        return  # No webhook configured, skip silently

    try:
        # Determine emoji and color based on status
        if status == 'success':
            emoji = '✅'
            color = 0x00FF00  # Green
        else:
            emoji = '❌'
            color = 0xFF0000  # Red

        # Build Discord embed
        embed = {
            'title': f'{emoji} Container Action: {action.capitalize()}',
            'description': message,
            'color': color,
            'fields': [
                {'name': 'Container', 'value': container_name, 'inline': True},
                {'name': 'Action', 'value': action.capitalize(), 'inline': True},
                {'name': 'Status', 'value': status.capitalize(), 'inline': True},
            ],
            'timestamp': datetime.utcnow().isoformat(),
            'footer': {'text': 'Chrontainer'}
        }

        if schedule_id:
            embed['fields'].append({'name': 'Schedule ID', 'value': str(schedule_id), 'inline': True})

        payload = {'embeds': [embed]}

        import requests
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code not in [200, 204]:
            logger.warning(f"Discord webhook returned status {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send Discord notification: {e}")

def send_ntfy_notification(container_name, action, status, message, schedule_id=None):
    """Send a ntfy.sh push notification"""
    ntfy_enabled = get_setting('ntfy_enabled', 'false')
    if ntfy_enabled != 'true':
        return

    ntfy_server = get_setting('ntfy_server', 'https://ntfy.sh')
    ntfy_topic = get_setting('ntfy_topic')

    if not ntfy_topic:
        return

    try:
        import requests

        if status == 'success':
            emoji = 'white_check_mark'
        else:
            emoji = 'x'

        title = f"Chrontainer: {action.capitalize()} {status.capitalize()}"
        body = f"{container_name}: {message}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"

        response = requests.post(
            url,
            data=body.encode('utf-8'),
            headers={
                'Title': title,
                'Priority': str(get_setting('ntfy_priority', '3')),
                'Tags': emoji
            },
            timeout=10
        )

        if response.status_code not in [200, 204]:
            logger.warning(f"ntfy notification returned status {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send ntfy notification: {e}")

def load_schedules():
    """Load all enabled schedules from database and add to scheduler"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, host_id, container_id, container_name, action, cron_expression, one_time, run_at FROM schedules WHERE enabled = 1')
    schedules = cursor.fetchall()
    conn.close()

    for schedule in schedules:
        schedule_id, host_id, container_id, container_name, action, cron_expr, one_time, run_at = schedule
        try:
            action_map = {
                'restart': restart_container,
                'start': start_container,
                'stop': stop_container,
                'pause': pause_container,
                'unpause': unpause_container,
                'update': update_container
            }
            action_func = action_map.get(action)
            if not action_func:
                logger.error(f"Unknown action '{action}' for schedule {schedule_id}")
                continue

            if one_time and run_at:
                from apscheduler.triggers.date import DateTrigger
                run_at_dt = datetime.fromisoformat(run_at) if isinstance(run_at, str) else run_at

                if run_at_dt <= datetime.now():
                    logger.info(f"Skipping past one-time schedule {schedule_id}")
                    continue

                trigger = DateTrigger(run_date=run_at_dt)

                def one_time_action(cid, cname, sid, hid, func=action_func):
                    func(cid, cname, sid, hid)
                    try:
                        conn = get_db()
                        cursor = conn.cursor()
                        cursor.execute('DELETE FROM schedules WHERE id = ?', (sid,))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        logger.error(f"Failed to delete one-time schedule {sid}: {e}")

                scheduler.add_job(
                    one_time_action,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True
                )
                logger.info(f"Loaded one-time schedule {schedule_id}: {container_name} at {run_at}")
            else:
                parts = cron_expr.split()
                if len(parts) != 5:
                    logger.error(f"Invalid cron expression for schedule {schedule_id}: {cron_expr}")
                    continue

                trigger = CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4]
                )

                scheduler.add_job(
                    action_func,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True
                )
                logger.info(f"Loaded schedule {schedule_id}: {container_name} - {action} - {cron_expr}")
        except Exception as e:
            logger.error(f"Failed to load schedule {schedule_id}: {e}")

# Routes
@app.route('/')
@login_required
def index():
    """Main dashboard"""
    try:
        container_list = []
        host_color_map = {}
        host_text_color_map = {}

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, color FROM hosts')
        for host_id_row, color in cursor.fetchall():
            resolved_color = color or HOST_DEFAULT_COLOR
            host_color_map[host_id_row] = resolved_color
            host_text_color_map[host_id_row] = get_contrast_text_color(resolved_color)
        conn.close()

        # Get containers from all hosts
        for host_id, host_name, docker_client in docker_manager.get_all_clients():
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers:
                    # Try to get the best image name
                    if container.image.tags:
                        image_name = container.image.tags[0]
                    else:
                        # Fallback to image name from Config if available
                        try:
                            image_name = container.attrs['Config']['Image']
                        except:
                            # Last resort: use short image ID
                            image_name = container.image.short_id.replace('sha256:', '')[:12]

                    # Extract IP addresses from all networks
                    ip_addresses = []
                    try:
                        networks = container.attrs['NetworkSettings']['Networks']
                        for network_name, network_info in networks.items():
                            if network_info.get('IPAddress'):
                                ip_addresses.append(network_info['IPAddress'])
                    except:
                        pass

                    # Extract stack/compose project name from labels
                    stack_name = 'N/A'
                    webui_url_from_label = None
                    try:
                        labels = container.attrs.get('Config', {}).get('Labels', {})
                        # Docker Compose adds this label
                        if 'com.docker.compose.project' in labels:
                            stack_name = labels['com.docker.compose.project']
                        # Check for webui URL in labels
                        if 'chrontainer.webui.url' in labels:
                            webui_url_from_label = labels['chrontainer.webui.url']
                    except:
                        pass

                    # Extract health status if available
                    health_status = None
                    try:
                        health = container.attrs.get('State', {}).get('Health', {})
                        if health:
                            health_status = health.get('Status')  # healthy, unhealthy, starting, or none
                    except:
                        pass

                    image_display = strip_image_tag(image_name)
                    image_version, version_source = get_image_version(container, image_name)
                    host_color = host_color_map.get(host_id, HOST_DEFAULT_COLOR)
                    host_text_color = host_text_color_map.get(host_id, get_contrast_text_color(host_color))

                    container_list.append({
                        'id': container.id[:12],
                        'name': container.name,
                        'status': container.status,
                        'health': health_status,
                        'image': image_name,
                        'image_display': image_display,
                        'image_version': image_version,
                        'image_version_source': version_source,
                        'created': container.attrs['Created'],
                        'host_id': host_id,
                        'host_name': host_name,
                        'host_color': host_color,
                        'host_text_color': host_text_color,
                        'ip_addresses': ', '.join(ip_addresses) if ip_addresses else 'N/A',
                        'stack': stack_name,
                        'webui_url_label': webui_url_from_label
                    })
            except Exception as e:
                logger.error(f"Error getting containers from host {host_name}: {e}")

        # Load tags and manual webui URLs for all containers
        conn = get_db()
        cursor = conn.cursor()

        # Get all tags for containers
        tags_map = {}  # Key: (container_id, host_id), Value: list of tags
        cursor.execute('''
            SELECT ct.container_id, ct.host_id, t.id, t.name, t.color
            FROM container_tags ct
            JOIN tags t ON ct.tag_id = t.id
        ''')
        for row in cursor.fetchall():
            key = (row[0], row[1])
            if key not in tags_map:
                tags_map[key] = []
            tags_map[key].append({'id': row[2], 'name': row[3], 'color': row[4]})

        # Get all manual webui URLs
        webui_map = {}  # Key: (container_id, host_id), Value: url
        cursor.execute('SELECT container_id, host_id, url FROM container_webui_urls')
        for row in cursor.fetchall():
            webui_map[(row[0], row[1])] = row[2]

        # Attach tags, webui URLs, and image links to containers
        for container in container_list:
            key = (container['id'], container['host_id'])
            container['tags'] = tags_map.get(key, [])
            # Manual URL takes precedence over label URL
            container['webui_url'] = webui_map.get(key) or container.get('webui_url_label')
            # Generate image registry/GitHub/docs links
            container['image_links'] = get_image_links(container['image'])

        # Get schedules with host info
        cursor.execute('''
            SELECT s.id, s.container_name, s.action, s.cron_expression, s.enabled, s.last_run, h.name, s.one_time, s.run_at
            FROM schedules s
            LEFT JOIN hosts h ON s.host_id = h.id
        ''')
        schedules = cursor.fetchall()
        conn.close()

        return render_template('index.html', containers=container_list, schedules=schedules, version=VERSION)
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/containers')
@api_key_or_login_required
def get_containers():
    """API endpoint to get all containers"""
    try:
        container_list = []
        host_color_map = {}
        host_text_color_map = {}

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, color FROM hosts')
        for host_id_row, color in cursor.fetchall():
            resolved_color = color or HOST_DEFAULT_COLOR
            host_color_map[host_id_row] = resolved_color
            host_text_color_map[host_id_row] = get_contrast_text_color(resolved_color)
        conn.close()

        for host_id, host_name, docker_client in docker_manager.get_all_clients():
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers:
                    # Try to get the best image name
                    if container.image.tags:
                        image_name = container.image.tags[0]
                    else:
                        # Fallback to image name from Config if available
                        try:
                            image_name = container.attrs['Config']['Image']
                        except:
                            # Last resort: use short image ID
                            image_name = container.image.short_id.replace('sha256:', '')[:12]

                    # Extract IP addresses from all networks
                    ip_addresses = []
                    try:
                        networks = container.attrs['NetworkSettings']['Networks']
                        for network_name, network_info in networks.items():
                            if network_info.get('IPAddress'):
                                ip_addresses.append(network_info['IPAddress'])
                    except:
                        pass

                    # Extract stack/compose project name and webui URL from labels
                    stack_name = 'N/A'
                    webui_url_from_label = None
                    try:
                        labels = container.attrs.get('Config', {}).get('Labels', {})
                        # Docker Compose adds this label
                        if 'com.docker.compose.project' in labels:
                            stack_name = labels['com.docker.compose.project']
                        # Check for webui URL in labels
                        if 'chrontainer.webui.url' in labels:
                            webui_url_from_label = labels['chrontainer.webui.url']
                    except:
                        pass

                    # Extract health status if available
                    health_status = None
                    try:
                        health = container.attrs.get('State', {}).get('Health', {})
                        if health:
                            health_status = health.get('Status')
                    except:
                        pass

                    image_display = strip_image_tag(image_name)
                    image_version, version_source = get_image_version(container, image_name)
                    host_color = host_color_map.get(host_id, HOST_DEFAULT_COLOR)
                    host_text_color = host_text_color_map.get(host_id, get_contrast_text_color(host_color))

                    container_list.append({
                        'id': container.id[:12],
                        'name': container.name,
                        'status': container.status,
                        'health': health_status,
                        'image': image_name,
                        'image_display': image_display,
                        'image_version': image_version,
                        'image_version_source': version_source,
                        'host_id': host_id,
                        'host_name': host_name,
                        'host_color': host_color,
                        'host_text_color': host_text_color,
                        'ip_addresses': ', '.join(ip_addresses) if ip_addresses else 'N/A',
                        'stack': stack_name,
                        'webui_url_label': webui_url_from_label
                    })
            except Exception as e:
                logger.error(f"Error getting containers from host {host_name}: {e}")

        # Load tags and manual webui URLs
        conn = get_db()
        cursor = conn.cursor()

        # Get all tags for containers
        tags_map = {}
        cursor.execute('''
            SELECT ct.container_id, ct.host_id, t.id, t.name, t.color
            FROM container_tags ct
            JOIN tags t ON ct.tag_id = t.id
        ''')
        for row in cursor.fetchall():
            key = (row[0], row[1])
            if key not in tags_map:
                tags_map[key] = []
            tags_map[key].append({'id': row[2], 'name': row[3], 'color': row[4]})

        # Get all manual webui URLs
        webui_map = {}
        cursor.execute('SELECT container_id, host_id, url FROM container_webui_urls')
        for row in cursor.fetchall():
            webui_map[(row[0], row[1])] = row[2]

        conn.close()

        # Attach tags, webui URLs, and image links to containers
        for container in container_list:
            key = (container['id'], container['host_id'])
            container['tags'] = tags_map.get(key, [])
            container['webui_url'] = webui_map.get(key) or container.get('webui_url_label')
            container['image_links'] = get_image_links(container['image'])

        return jsonify(container_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/container/<container_id>/restart', methods=['POST'])
@api_key_or_login_required
def api_restart_container(container_id):
    """API endpoint to restart a container"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    data = request.json or {}
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = restart_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/start', methods=['POST'])
@api_key_or_login_required
def api_start_container(container_id):
    """API endpoint to start a container"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    data = request.json or {}
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = start_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/stop', methods=['POST'])
@api_key_or_login_required
def api_stop_container(container_id):
    """API endpoint to stop a container"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    data = request.json or {}
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = stop_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/pause', methods=['POST'])
@api_key_or_login_required
def api_pause_container(container_id):
    """API endpoint to pause a container"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    data = request.json or {}
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = pause_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/unpause', methods=['POST'])
@api_key_or_login_required
def api_unpause_container(container_id):
    """API endpoint to unpause a container"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    data = request.json or {}
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = unpause_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/check-update', methods=['GET'])
def api_check_container_update(container_id):
    """API endpoint to check if a container has an update available"""
    host_id = request.args.get('host_id', 1, type=int)

    try:
        client = docker_manager.get_client(host_id)
        if not client:
            return jsonify({'error': 'Cannot connect to Docker host'}), 500

        container = client.containers.get(container_id)
        has_update, remote_digest, remote_version, error = check_for_update(container, client)

        if error:
            return jsonify({'has_update': False, 'error': error})

        return jsonify({
            'has_update': has_update,
            'remote_digest': remote_digest,
            'remote_version': remote_version
        })

    except docker.errors.NotFound:
        return jsonify({'error': 'Container not found'}), 404
    except Exception as e:
        logger.error(f"Error checking for update: {e}")
        return jsonify({'error': 'Failed to check for updates'}), 500

@app.route('/api/containers/check-updates', methods=['GET'])
@login_required
def api_check_all_updates():
    """API endpoint to check for updates on all containers"""
    results = []

    try:
        for host_id, host_name, docker_client in docker_manager.get_all_clients():
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers:
                    container_id = container.id[:12]
                    try:
                        has_update, remote_digest, remote_version, error = check_for_update(container, docker_client)
                        results.append({
                            'container_id': container_id,
                            'container_name': container.name,
                            'host_id': host_id,
                            'host_name': host_name,
                            'has_update': has_update,
                            'remote_version': remote_version,
                            'error': error
                        })
                    except Exception as e:
                        results.append({
                            'container_id': container_id,
                            'container_name': container.name,
                            'host_id': host_id,
                            'host_name': host_name,
                            'has_update': False,
                            'remote_version': None,
                            'error': str(e)
                        })
            except Exception as e:
                logger.error(f"Error checking updates for host {host_name}: {e}")

        return jsonify({
            'success': True,
            'results': results,
            'total': len(results),
            'updates_available': sum(1 for r in results if r.get('has_update'))
        })
    except Exception as e:
        logger.error(f"Error in bulk update check: {e}")
        return jsonify({'error': 'Failed to check for updates'}), 500

@app.route('/api/container/<container_id>/update', methods=['POST'])
@api_key_or_login_required
def api_update_container(container_id):
    """API endpoint to update a container"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    data = request.json or {}
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)

    try:
        success, message = update_container(container_id, container_name, host_id)
        return jsonify({'success': success, 'message': message})

    except Exception as e:
        logger.error(f"Error updating container: {e}")
        return jsonify({'success': False, 'message': f'Update failed: {str(e)}'}), 500

@app.route('/api/container/<container_id>/logs', methods=['GET'])
def api_get_container_logs(container_id):
    """API endpoint to get container logs"""
    host_id = request.args.get('host_id', 1, type=int)
    tail = request.args.get('tail', 100, type=int)  # Default to last 100 lines
    timestamps = request.args.get('timestamps', 'true').lower() == 'true'

    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            return jsonify({'error': f'Cannot connect to Docker host (ID: {host_id}). Please check the host connection in Settings > Hosts.'}), 500

        container = docker_client.containers.get(container_id)
        logs = container.logs(
            tail=tail,
            timestamps=timestamps,
            stdout=True,
            stderr=True
        ).decode('utf-8')

        return jsonify({
            'success': True,
            'logs': logs,
            'container_id': container_id,
            'container_name': container.name
        })
    except docker.errors.NotFound:
        logger.error(f"Container {container_id} not found on host {host_id}")
        return jsonify({'error': f'Container not found. It may have been removed.'}), 404
    except docker.errors.APIError as e:
        logger.error(f"Docker API error getting logs for {container_id}: {e}")
        return jsonify({'error': 'Failed to retrieve container logs. The container may not be running or accessible.'}), 500
    except Exception as e:
        logger.error(f"Failed to get logs for container {container_id}: {e}")
        return jsonify({'error': 'Failed to retrieve container logs. Please try again.'}), 500

@app.route('/api/container/<container_id>/stats', methods=['GET'])
@api_key_or_login_required
def api_get_container_stats(container_id):
    """API endpoint to get container resource stats"""
    host_id = request.args.get('host_id', 1, type=int)

    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            return jsonify({'error': 'Cannot connect to Docker host'}), 500

        container = docker_client.containers.get(container_id)

        if container.status != 'running':
            return jsonify({
                'cpu_percent': None,
                'memory_percent': None,
                'memory_mb': None,
                'status': container.status
            })

        stats = container.stats(stream=False)

        cpu_percent = 0.0
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
            online_cpus = stats['cpu_stats'].get('online_cpus', 1)
            if system_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
        except (KeyError, ZeroDivisionError):
            cpu_percent = 0.0

        memory_percent = 0.0
        memory_mb = 0.0
        try:
            memory_usage = stats['memory_stats'].get('usage', 0)
            memory_limit = stats['memory_stats'].get('limit', 1)
            cache = stats['memory_stats'].get('stats', {}).get('cache', 0)
            memory_usage = memory_usage - cache
            memory_percent = (memory_usage / memory_limit) * 100
            memory_mb = memory_usage / (1024 * 1024)
        except (KeyError, ZeroDivisionError):
            pass

        return jsonify({
            'cpu_percent': round(cpu_percent, 1),
            'memory_percent': round(memory_percent, 1),
            'memory_mb': round(memory_mb, 1),
            'status': container.status
        })

    except docker.errors.NotFound:
        return jsonify({'error': 'Container not found'}), 404
    except Exception as e:
        logger.error(f"Failed to get stats for container {container_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/containers/stats', methods=['GET'])
@api_key_or_login_required
def api_get_all_container_stats():
    """API endpoint to get stats for all running containers"""
    results = {}

    for host_id, host_name, docker_client in docker_manager.get_all_clients():
        try:
            containers = docker_client.containers.list(all=False)
            for container in containers:
                container_id = container.id[:12]
                try:
                    stats = container.stats(stream=False)

                    cpu_percent = 0.0
                    try:
                        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
                        system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
                        online_cpus = stats['cpu_stats'].get('online_cpus', 1)
                        if system_delta > 0:
                            cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
                    except (KeyError, ZeroDivisionError):
                        pass

                    memory_percent = 0.0
                    memory_mb = 0.0
                    try:
                        memory_usage = stats['memory_stats'].get('usage', 0)
                        memory_limit = stats['memory_stats'].get('limit', 1)
                        cache = stats['memory_stats'].get('stats', {}).get('cache', 0)
                        memory_usage = memory_usage - cache
                        memory_percent = (memory_usage / memory_limit) * 100
                        memory_mb = memory_usage / (1024 * 1024)
                    except (KeyError, ZeroDivisionError):
                        pass

                    results[f"{container_id}_{host_id}"] = {
                        'cpu_percent': round(cpu_percent, 1),
                        'memory_percent': round(memory_percent, 1),
                        'memory_mb': round(memory_mb, 1)
                    }
                except Exception as e:
                    logger.debug(f"Failed to get stats for {container.name}: {e}")
        except Exception as e:
            logger.error(f"Failed to get containers from host {host_name}: {e}")

    return jsonify(results)

@app.route('/api/schedule', methods=['POST'])
@api_key_or_login_required
def add_schedule():
    """Add a new schedule"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    data = request.json
    container_id = sanitize_string(data.get('container_id', ''), max_length=64)
    container_name = sanitize_string(data.get('container_name', ''), max_length=255)
    action = sanitize_string(data.get('action', 'restart'), max_length=20)
    cron_expression = sanitize_string(data.get('cron_expression', ''), max_length=50)
    host_id = data.get('host_id', 1)
    one_time = data.get('one_time', False)
    run_at = data.get('run_at')

    # Validate container ID
    valid, error = validate_container_id(container_id)
    if not valid:
        return jsonify({'error': error}), 400

    # Validate container name
    valid, error = validate_container_name(container_name)
    if not valid:
        return jsonify({'error': error}), 400

    # Validate action
    if action not in ['restart', 'start', 'stop', 'pause', 'unpause', 'update']:
        return jsonify({'error': 'Invalid action. Must be one of: restart, start, stop, pause, unpause, update'}), 400

    if one_time:
        if not run_at:
            return jsonify({'error': 'run_at is required for one-time schedules'}), 400
        try:
            run_at_dt = datetime.fromisoformat(run_at.replace('Z', '+00:00'))
            if run_at_dt <= datetime.now(run_at_dt.tzinfo):
                return jsonify({'error': 'run_at must be in the future'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid run_at format. Use ISO format.'}), 400
    else:
        valid, error = validate_cron_expression(cron_expression)
        if not valid:
            return jsonify({'error': error}), 400

        try:
            parts = cron_expression.split()
            trigger = CronTrigger(
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4]
            )
        except ValueError:
            return jsonify({'error': 'Invalid cron expression values. Please check your cron syntax. Common patterns: "0 2 * * *" (2 AM daily), "*/15 * * * *" (every 15 min)'}), 400
        except Exception:
            return jsonify({'error': 'Failed to parse cron expression. Please verify your syntax using a tool like crontab.guru'}), 400

    # Save to database
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO schedules
               (host_id, container_id, container_name, action, cron_expression, one_time, run_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (host_id, container_id, container_name, action,
             cron_expression if not one_time else '',
             1 if one_time else 0,
             run_at if one_time else None)
        )
        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Add to scheduler with the appropriate action function
        action_map = {
            'restart': restart_container,
            'start': start_container,
            'stop': stop_container,
            'pause': pause_container,
            'unpause': unpause_container,
            'update': update_container
        }
        action_func = action_map.get(action)
        if not action_func:
            return jsonify({'error': f'Invalid action: {action}'}), 400

        if one_time:
            from apscheduler.triggers.date import DateTrigger
            trigger = DateTrigger(run_date=run_at_dt)

            def one_time_action(cid, cname, sid, hid, func=action_func):
                func(cid, cname, sid, hid)
                try:
                    conn = get_db()
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM schedules WHERE id = ?', (sid,))
                    conn.commit()
                    conn.close()
                    logger.info(f"One-time schedule {sid} executed and deleted")
                except Exception as e:
                    logger.error(f"Failed to delete one-time schedule {sid}: {e}")

            scheduler.add_job(
                one_time_action,
                trigger,
                args=[container_id, container_name, schedule_id, host_id],
                id=f"schedule_{schedule_id}",
                replace_existing=True
            )
        else:
            scheduler.add_job(
                action_func,
                trigger,
                args=[container_id, container_name, schedule_id, host_id],
                id=f"schedule_{schedule_id}",
                replace_existing=True
            )

        logger.info(f"Added {'one-time' if one_time else 'recurring'} schedule {schedule_id}")
        return jsonify({'success': True, 'schedule_id': schedule_id})
    except Exception as e:
        logger.error(f"Failed to add schedule: {e}")
        return jsonify({'error': 'Failed to create schedule. Please check the logs for details.'}), 500

@app.route('/api/schedule/<int:schedule_id>', methods=['DELETE'])
@api_key_or_login_required
def delete_schedule(schedule_id):
    """Delete a schedule"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    try:
        # Remove from scheduler
        try:
            scheduler.remove_job(f"schedule_{schedule_id}")
        except:
            pass  # Job might not exist in scheduler
        
        # Remove from database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM schedules WHERE id = ?', (schedule_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"Deleted schedule {schedule_id}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete schedule: {e}")
        return jsonify({'error': 'Failed to delete schedule. It may have already been removed.'}), 500

@app.route('/api/schedule/<int:schedule_id>/toggle', methods=['POST'])
@api_key_or_login_required
def toggle_schedule(schedule_id):
    """Enable/disable a schedule"""
    if getattr(request, 'api_key_auth', False) and request.api_key_permissions == 'read':
        return jsonify({'error': 'API key does not have write permission'}), 403
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT enabled, host_id, container_id, container_name, action, cron_expression, one_time, run_at FROM schedules WHERE id = ?', (schedule_id,))
        result = cursor.fetchone()

        if not result:
            return jsonify({'error': 'Schedule not found'}), 404

        enabled, host_id, container_id, container_name, action, cron_expression, one_time, run_at = result
        new_enabled = 0 if enabled else 1

        cursor.execute('UPDATE schedules SET enabled = ? WHERE id = ?', (new_enabled, schedule_id))
        conn.commit()
        conn.close()

        # Update scheduler
        if new_enabled:
            action_map = {
                'restart': restart_container,
                'start': start_container,
                'stop': stop_container,
                'pause': pause_container,
                'unpause': unpause_container,
                'update': update_container
            }
            action_func = action_map.get(action)
            if not action_func:
                return jsonify({'error': f'Invalid action: {action}'}), 400

            if one_time and run_at:
                from apscheduler.triggers.date import DateTrigger
                run_at_dt = datetime.fromisoformat(run_at) if isinstance(run_at, str) else run_at

                if run_at_dt <= datetime.now():
                    return jsonify({'error': 'run_at must be in the future'}), 400

                trigger = DateTrigger(run_date=run_at_dt)

                def one_time_action(cid, cname, sid, hid, func=action_func):
                    func(cid, cname, sid, hid)
                    try:
                        conn = get_db()
                        cursor = conn.cursor()
                        cursor.execute('DELETE FROM schedules WHERE id = ?', (sid,))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        logger.error(f"Failed to delete one-time schedule {sid}: {e}")

                scheduler.add_job(
                    one_time_action,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True
                )
            else:
                parts = cron_expression.split()
                trigger = CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4]
                )
                scheduler.add_job(
                    action_func,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True
                )
        else:
            try:
                scheduler.remove_job(f"schedule_{schedule_id}")
            except:
                pass

        return jsonify({'success': True, 'enabled': bool(new_enabled)})
    except Exception as e:
        logger.error(f"Failed to toggle schedule {schedule_id}: {e}")
        return jsonify({'error': 'Failed to toggle schedule. Please refresh the page and try again.'}), 500

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get all settings"""
    try:
        webhook_url = get_setting('discord_webhook_url', '')
        return jsonify({
            'discord_webhook_url': webhook_url,
            'ntfy_enabled': get_setting('ntfy_enabled', 'false'),
            'ntfy_server': get_setting('ntfy_server', 'https://ntfy.sh'),
            'ntfy_topic': get_setting('ntfy_topic', ''),
            'ntfy_priority': get_setting('ntfy_priority', '3')
        })
    except Exception as e:
        logger.error(f"Failed to get settings: {e}")
        return jsonify({'error': 'Failed to load settings. Please check the database connection.'}), 500

@app.route('/api/settings/discord', methods=['POST'])
@login_required
def update_discord_settings():
    """Update Discord webhook settings"""
    try:
        data = request.json
        webhook_url = sanitize_string(data.get('webhook_url', ''), max_length=2048).strip()

        # Validate webhook URL
        valid, error = validate_webhook_url(webhook_url)
        if not valid:
            return jsonify({'error': error}), 400

        set_setting('discord_webhook_url', webhook_url)
        logger.info(f"Discord webhook URL updated")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to update Discord settings: {e}")
        return jsonify({'error': 'Failed to save Discord webhook settings. Please try again.'}), 500

@app.route('/api/settings/ntfy', methods=['POST'])
@login_required
def update_ntfy_settings():
    """Update ntfy notification settings"""
    try:
        data = request.json

        ntfy_enabled = data.get('enabled', False)
        ntfy_server = sanitize_string(data.get('server', 'https://ntfy.sh'), max_length=500).strip()
        ntfy_topic = sanitize_string(data.get('topic', ''), max_length=100).strip()
        ntfy_priority = data.get('priority', 3)

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

        logger.info("ntfy settings updated")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to update ntfy settings: {e}")
        return jsonify({'error': 'Failed to save settings'}), 500

@app.route('/api/settings/ntfy/test', methods=['POST'])
@login_required
def test_ntfy():
    """Test ntfy notification"""
    try:
        ntfy_server = get_setting('ntfy_server', 'https://ntfy.sh')
        ntfy_topic = get_setting('ntfy_topic')

        if not ntfy_topic:
            return jsonify({'error': 'ntfy topic not configured'}), 400

        import requests
        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"

        response = requests.post(
            url,
            data="This is a test notification from Chrontainer!".encode('utf-8'),
            headers={
                'Title': 'Chrontainer Test',
                'Priority': '3',
                'Tags': 'bell'
            },
            timeout=10
        )

        if response.status_code in [200, 204]:
            return jsonify({'success': True, 'message': 'Test notification sent'})
        return jsonify({'error': f'Server returned status {response.status_code}'}), 400
    except Exception as e:
        logger.error(f"Failed to test ntfy: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/discord/test', methods=['POST'])
def test_discord_webhook():
    """Test Discord webhook"""
    try:
        webhook_url = get_setting('discord_webhook_url')
        if not webhook_url:
            return jsonify({'error': 'No Discord webhook URL configured. Please add a webhook URL in the settings first.'}), 400

        # Send a test notification
        send_discord_notification(
            container_name='test-container',
            action='test',
            status='success',
            message='This is a test notification from Chrontainer!'
        )
        return jsonify({'success': True, 'message': 'Test notification sent'})
    except Exception as e:
        logger.error(f"Failed to test Discord webhook: {e}")
        return jsonify({'error': 'Failed to send test notification. Please check your webhook URL and network connection.'}), 500

@app.route('/api/keys', methods=['GET'])
@login_required
def list_api_keys():
    """List all API keys for current user"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, key_prefix, permissions, last_used, expires_at, created_at
            FROM api_keys WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (current_user.id,))
        keys = cursor.fetchall()
        conn.close()

        return jsonify([{
            'id': k[0],
            'name': k[1],
            'key_prefix': k[2],
            'permissions': k[3],
            'last_used': k[4],
            'expires_at': k[5],
            'created_at': k[6]
        } for k in keys])
    except Exception as e:
        logger.error(f"Failed to list API keys: {e}")
        return jsonify({'error': 'Failed to list keys'}), 500


@app.route('/api/keys', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
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

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO api_keys (user_id, name, key_hash, key_prefix, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (current_user.id, name, key_hash, key_prefix, permissions, expires_at))
        key_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"API key created: {key_prefix}... for user {current_user.username}")

        return jsonify({
            'id': key_id,
            'name': name,
            'key': full_key,
            'key_prefix': key_prefix,
            'permissions': permissions,
            'expires_at': expires_at,
            'message': 'Save this key now - it will not be shown again!'
        })
    except Exception as e:
        logger.error(f"Failed to create API key: {e}")
        return jsonify({'error': 'Failed to create key'}), 500


@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """Delete an API key"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM api_keys WHERE id = ?', (key_id,))
        result = cursor.fetchone()

        if not result:
            conn.close()
            return jsonify({'error': 'API key not found'}), 404

        if result[0] != current_user.id and current_user.role != 'admin':
            conn.close()
            return jsonify({'error': 'Not authorized to delete this key'}), 403

        cursor.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
        conn.commit()
        conn.close()

        logger.info(f"API key {key_id} deleted by user {current_user.username}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete API key: {e}")
        return jsonify({'error': 'Failed to delete key'}), 500


@app.route('/webhook/<token>', methods=['POST', 'GET'])
def trigger_webhook(token):
    """Trigger a webhook action - no auth required, uses token"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, container_id, host_id, action, enabled
            FROM webhooks WHERE token = ?
        ''', (token,))
        webhook = cursor.fetchone()

        if not webhook:
            conn.close()
            return jsonify({'error': 'Invalid webhook'}), 404

        webhook_id, name, container_id, host_id, action, enabled = webhook

        if not enabled:
            conn.close()
            return jsonify({'error': 'Webhook is disabled'}), 403

        override_container = None
        override_host = None

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
            conn.close()
            return jsonify({'error': 'No container specified'}), 400

        docker_client = docker_manager.get_client(target_host)
        if not docker_client:
            conn.close()
            return jsonify({'error': 'Docker host not available'}), 503

        try:
            container = docker_client.containers.get(target_container)
            container_name = container.name
        except docker.errors.NotFound:
            conn.close()
            return jsonify({'error': 'Container not found'}), 404

        cursor.execute('''
            UPDATE webhooks
            SET last_triggered = CURRENT_TIMESTAMP, trigger_count = trigger_count + 1
            WHERE id = ?
        ''', (webhook_id,))
        conn.commit()
        conn.close()

        action_map = {
            'restart': restart_container,
            'start': start_container,
            'stop': stop_container,
            'pause': pause_container,
            'unpause': unpause_container,
            'update': update_container
        }

        action_func = action_map.get(action)
        if not action_func:
            return jsonify({'error': f'Unknown action: {action}'}), 400

        thread = threading.Thread(
            target=action_func,
            args=[target_container, container_name, None, target_host]
        )
        thread.start()

        logger.info(f"Webhook '{name}' triggered: {action} on {container_name}")

        return jsonify({
            'success': True,
            'webhook': name,
            'action': action,
            'container': container_name,
            'message': f'{action.capitalize()} triggered for {container_name}'
        })

    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'error': 'Webhook execution failed'}), 500


@app.route('/api/webhooks', methods=['GET'])
@login_required
def list_webhooks():
    """List all webhooks"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT w.id, w.name, w.token, w.container_id, w.host_id, w.action,
                   w.enabled, w.last_triggered, w.trigger_count, w.created_at, h.name
            FROM webhooks w
            LEFT JOIN hosts h ON w.host_id = h.id
            ORDER BY w.created_at DESC
        ''')
        webhooks = cursor.fetchall()
        conn.close()

        return jsonify([{
            'id': w[0],
            'name': w[1],
            'token': w[2],
            'container_id': w[3],
            'host_id': w[4],
            'action': w[5],
            'enabled': bool(w[6]),
            'last_triggered': w[7],
            'trigger_count': w[8],
            'created_at': w[9],
            'host_name': w[10]
        } for w in webhooks])
    except Exception as e:
        logger.error(f"Failed to list webhooks: {e}")
        return jsonify({'error': 'Failed to list webhooks'}), 500


@app.route('/api/webhooks', methods=['POST'])
@login_required
def create_webhook():
    """Create a new webhook"""
    try:
        data = request.json or {}
        name = sanitize_string(data.get('name', ''), max_length=100)
        container_id = sanitize_string(data.get('container_id', ''), max_length=64) or None
        host_id = data.get('host_id')
        action = sanitize_string(data.get('action', 'restart'), max_length=20)

        if not name:
            return jsonify({'error': 'Name is required'}), 400

        if action not in ['restart', 'start', 'stop', 'pause', 'unpause', 'update']:
            return jsonify({'error': 'Invalid action'}), 400

        token = secrets.token_urlsafe(24)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO webhooks (name, token, container_id, host_id, action)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, token, container_id, host_id, action))
        webhook_id = cursor.lastrowid
        conn.commit()
        conn.close()

        webhook_url = f"{request.host_url}webhook/{token}"

        logger.info(f"Webhook created: {name}")

        return jsonify({
            'id': webhook_id,
            'name': name,
            'token': token,
            'url': webhook_url,
            'action': action
        })
    except Exception as e:
        logger.error(f"Failed to create webhook: {e}")
        return jsonify({'error': 'Failed to create webhook'}), 500


@app.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
@login_required
def delete_webhook(webhook_id):
    """Delete a webhook"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,))
        conn.commit()
        conn.close()

        logger.info(f"Webhook {webhook_id} deleted")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete webhook: {e}")
        return jsonify({'error': 'Failed to delete webhook'}), 500


@app.route('/api/webhooks/<int:webhook_id>/toggle', methods=['POST'])
@login_required
def toggle_webhook(webhook_id):
    """Enable/disable a webhook"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE webhooks SET enabled = NOT enabled WHERE id = ?', (webhook_id,))
        cursor.execute('SELECT enabled FROM webhooks WHERE id = ?', (webhook_id,))
        result = cursor.fetchone()
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'enabled': bool(result[0])})
    except Exception as e:
        logger.error(f"Failed to toggle webhook: {e}")
        return jsonify({'error': 'Failed to toggle webhook'}), 500

@app.route('/api/hosts/<int:host_id>/metrics', methods=['GET'])
@api_key_or_login_required
def get_host_metrics(host_id):
    """Get system metrics for a Docker host"""
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            return jsonify({'error': 'Cannot connect to Docker host'}), 503

        info = docker_client.info()

        try:
            disk_usage = docker_client.df()
        except Exception:
            disk_usage = None

        containers_running = info.get('ContainersRunning', 0)
        containers_paused = info.get('ContainersPaused', 0)
        containers_stopped = info.get('ContainersStopped', 0)

        mem_total = info.get('MemTotal', 0)

        mem_used_by_containers = 0
        try:
            for container in docker_client.containers.list():
                try:
                    stats = container.stats(stream=False)
                    mem_used_by_containers += stats.get('memory_stats', {}).get('usage', 0)
                except Exception:
                    pass
        except Exception:
            pass

        cpus = info.get('NCPU', 0)

        images_size = 0
        containers_size = 0
        volumes_size = 0
        build_cache_size = 0

        if disk_usage:
            for img in disk_usage.get('Images', []) or []:
                images_size += img.get('Size', 0) or 0

            for cont in disk_usage.get('Containers', []) or []:
                containers_size += cont.get('SizeRw', 0) or 0

            for vol in disk_usage.get('Volumes', []) or []:
                volumes_size += vol.get('UsageData', {}).get('Size', 0) or 0

            for cache in disk_usage.get('BuildCache', []) or []:
                build_cache_size += cache.get('Size', 0) or 0

        return jsonify({
            'host_id': host_id,
            'name': info.get('Name', 'Unknown'),
            'os': info.get('OperatingSystem', 'Unknown'),
            'architecture': info.get('Architecture', 'Unknown'),
            'docker_version': info.get('ServerVersion', 'Unknown'),
            'kernel_version': info.get('KernelVersion', 'Unknown'),
            'cpus': cpus,
            'memory': {
                'total_bytes': mem_total,
                'total_gb': round(mem_total / (1024**3), 2),
                'used_by_containers_bytes': mem_used_by_containers,
                'used_by_containers_gb': round(mem_used_by_containers / (1024**3), 2)
            },
            'containers': {
                'running': containers_running,
                'paused': containers_paused,
                'stopped': containers_stopped,
                'total': containers_running + containers_paused + containers_stopped
            },
            'disk': {
                'images_bytes': images_size,
                'images_gb': round(images_size / (1024**3), 2),
                'containers_bytes': containers_size,
                'containers_gb': round(containers_size / (1024**3), 2),
                'volumes_bytes': volumes_size,
                'volumes_gb': round(volumes_size / (1024**3), 2),
                'build_cache_bytes': build_cache_size,
                'build_cache_gb': round(build_cache_size / (1024**3), 2),
                'total_bytes': images_size + containers_size + volumes_size + build_cache_size,
                'total_gb': round((images_size + containers_size + volumes_size + build_cache_size) / (1024**3), 2)
            },
            'images_count': info.get('Images', 0)
        })

    except Exception as e:
        logger.error(f"Failed to get host metrics for host {host_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts/metrics', methods=['GET'])
@api_key_or_login_required
def get_all_hosts_metrics():
    """Get metrics for all enabled hosts"""
    results = []

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM hosts WHERE enabled = 1')
    hosts = cursor.fetchall()
    conn.close()

    for host_id, host_name in hosts:
        try:
            docker_client = docker_manager.get_client(host_id)
            if not docker_client:
                results.append({
                    'host_id': host_id,
                    'name': host_name,
                    'status': 'offline',
                    'error': 'Cannot connect'
                })
                continue

            info = docker_client.info()

            results.append({
                'host_id': host_id,
                'name': host_name,
                'status': 'online',
                'os': info.get('OperatingSystem', 'Unknown'),
                'cpus': info.get('NCPU', 0),
                'memory_gb': round(info.get('MemTotal', 0) / (1024**3), 2),
                'containers_running': info.get('ContainersRunning', 0),
                'containers_total': info.get('Containers', 0),
                'images': info.get('Images', 0)
            })
        except Exception as e:
            results.append({
                'host_id': host_id,
                'name': host_name,
                'status': 'error',
                'error': str(e)
            })

    return jsonify(results)

@app.route('/api/hosts', methods=['GET'])
@api_key_or_login_required
def get_hosts():
    """Get all Docker hosts"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, url, enabled, color, last_seen, created_at FROM hosts ORDER BY id')
        hosts = cursor.fetchall()
        conn.close()

        host_list = []
        for host in hosts:
            host_list.append({
                'id': host[0],
                'name': host[1],
                'url': host[2],
                'enabled': bool(host[3]),
                'color': host[4],
                'last_seen': host[5],
                'created_at': host[6]
            })
        return jsonify(host_list)
    except Exception as e:
        logger.error(f"Failed to get hosts: {e}")
        return jsonify({'error': 'Failed to load Docker hosts. Please check the database connection.'}), 500

@app.route('/api/hosts', methods=['POST'])
@login_required
def add_host():
    """Add a new Docker host"""
    try:
        data = request.json
        name = sanitize_string(data.get('name', ''), max_length=100).strip()
        url = sanitize_string(data.get('url', ''), max_length=500).strip()
        color = sanitize_string(data.get('color', HOST_DEFAULT_COLOR), max_length=7).strip()

        # Validate name
        if not name or len(name) < 1:
            return jsonify({'error': 'Host name is required'}), 400
        if len(name) > 100:
            return jsonify({'error': 'Host name is too long (max 100 characters)'}), 400

        # Validate URL
        valid, error = validate_url(url)
        if not valid:
            return jsonify({'error': 'Host URL is required (e.g., tcp://192.168.1.100:2375 or unix:///var/run/docker.sock)'}), 400

        valid, error = validate_color(color)
        if not valid:
            return jsonify({'error': error}), 400

        # Test connection first
        success, message = docker_manager.test_connection(url)
        if not success:
            return jsonify({'error': f'Connection test failed: {message}. Please ensure the Docker host is running and accessible, and that you have set up a socket-proxy for remote hosts.'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO hosts (name, url, enabled, color, last_seen) VALUES (?, ?, 1, ?, ?)',
            (name, url, color, datetime.now())
        )
        host_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"Added new host: {name} ({url})")
        return jsonify({'success': True, 'host_id': host_id})
    except sqlite3.IntegrityError:
        logger.error(f"Duplicate host: {name} or {url}")
        return jsonify({'error': f'A host with this name or URL already exists'}), 400
    except Exception as e:
        logger.error(f"Failed to add host: {e}")
        return jsonify({'error': 'Failed to add Docker host. Please try again.'}), 500

@app.route('/api/hosts/<int:host_id>', methods=['PUT'])
@login_required
def update_host(host_id):
    """Update a Docker host"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        url = data.get('url', '').strip()
        color = data.get('color', HOST_DEFAULT_COLOR).strip()
        enabled = data.get('enabled', True)

        if not name:
            return jsonify({'error': 'Host name is required'}), 400
        if not url:
            return jsonify({'error': 'Host URL is required'}), 400
        valid, error = validate_color(color)
        if not valid:
            return jsonify({'error': error}), 400

        # Don't allow disabling the local host
        if host_id == 1 and not enabled:
            return jsonify({'error': 'Cannot disable the local Docker host (ID: 1). This host is required for Chrontainer to function.'}), 400

        # Test connection if URL changed
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT url FROM hosts WHERE id = ?', (host_id,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return jsonify({'error': f'Host with ID {host_id} not found'}), 404
        current_url = result[0]
        conn.close()

        if url != current_url:
            success, message = docker_manager.test_connection(url)
            if not success:
                return jsonify({'error': f'Connection test failed: {message}. Please verify the Docker host URL and network connectivity.'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE hosts SET name = ?, url = ?, enabled = ?, color = ? WHERE id = ?',
            (name, url, 1 if enabled else 0, color, host_id)
        )
        conn.commit()
        conn.close()

        # Clear cached client for this host
        docker_manager.clear_cache(host_id)

        logger.info(f"Updated host {host_id}: {name}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to update host: {e}")
        return jsonify({'error': 'Failed to update Docker host. Please try again.'}), 500

@app.route('/api/hosts/<int:host_id>', methods=['DELETE'])
@login_required
def delete_host(host_id):
    """Delete a Docker host"""
    try:
        # Don't allow deleting the local host
        if host_id == 1:
            return jsonify({'error': 'Cannot delete the local Docker host (ID: 1). This host is required for Chrontainer to function.'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Check if host has any schedules
        cursor.execute('SELECT COUNT(*) FROM schedules WHERE host_id = ?', (host_id,))
        count = cursor.fetchone()[0]
        if count > 0:
            conn.close()
            return jsonify({'error': f'Cannot delete host with {count} active schedule(s). Please delete or move the schedules first.'}), 400

        cursor.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
        conn.commit()
        conn.close()

        # Clear cached client
        docker_manager.clear_cache(host_id)

        logger.info(f"Deleted host {host_id}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete host: {e}")
        return jsonify({'error': 'Failed to delete Docker host. Please try again.'}), 500

@app.route('/api/hosts/<int:host_id>/test', methods=['POST'])
@login_required
def test_host_connection(host_id):
    """Test connection to a Docker host"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT url FROM hosts WHERE id = ?', (host_id,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({'error': 'Host not found'}), 404

        url = result[0]
        success, message = docker_manager.test_connection(url)

        if success:
            # Update last_seen
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('UPDATE hosts SET last_seen = ? WHERE id = ?', (datetime.now(), host_id))
            conn.commit()
            conn.close()

        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== Tags API =====

@app.route('/api/tags', methods=['GET'])
@api_key_or_login_required
def get_tags():
    """Get all tags"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, color FROM tags ORDER BY name')
        tags = [{'id': row[0], 'name': row[1], 'color': row[2]} for row in cursor.fetchall()]
        conn.close()
        return jsonify(tags)
    except Exception as e:
        logger.error(f"Failed to get tags: {e}")
        return jsonify({'error': 'Failed to load tags. Please check the database connection.'}), 500

@app.route('/api/tags', methods=['POST'])
def create_tag():
    """Create a new tag"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        color = data.get('color', '#3498db').strip()

        if not name:
            return jsonify({'error': 'Tag name is required'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO tags (name, color) VALUES (?, ?)', (name, color))
        tag_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'id': tag_id, 'name': name, 'color': color})
    except sqlite3.IntegrityError:
        return jsonify({'error': f'A tag named "{name}" already exists'}), 400
    except Exception as e:
        logger.error(f"Failed to create tag: {e}")
        return jsonify({'error': 'Failed to create tag. Please try again.'}), 500

@app.route('/api/tags/<int:tag_id>', methods=['DELETE'])
def delete_tag(tag_id):
    """Delete a tag"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM tags WHERE id = ?', (tag_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete tag: {e}")
        return jsonify({'error': 'Failed to delete tag. Please try again.'}), 500

@app.route('/api/containers/<container_id>/<int:host_id>/tags', methods=['GET'])
def get_container_tags(container_id, host_id):
    """Get tags for a specific container"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT t.id, t.name, t.color
            FROM tags t
            JOIN container_tags ct ON t.id = ct.tag_id
            WHERE ct.container_id = ? AND ct.host_id = ?
        ''', (container_id, host_id))
        tags = [{'id': row[0], 'name': row[1], 'color': row[2]} for row in cursor.fetchall()]
        conn.close()
        return jsonify(tags)
    except Exception as e:
        logger.error(f"Failed to get container tags: {e}")
        return jsonify({'error': 'Failed to load container tags.'}), 500

@app.route('/api/containers/<container_id>/<int:host_id>/tags', methods=['POST'])
def add_container_tag(container_id, host_id):
    """Add a tag to a container"""
    try:
        data = request.json
        tag_id = data.get('tag_id')

        if not tag_id:
            return jsonify({'error': 'Tag ID is required. Please select a tag to add.'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT OR IGNORE INTO container_tags (container_id, host_id, tag_id) VALUES (?, ?, ?)',
            (container_id, host_id, tag_id)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to add container tag: {e}")
        return jsonify({'error': 'Failed to add tag to container. Please try again.'}), 500

@app.route('/api/containers/<container_id>/<int:host_id>/tags/<int:tag_id>', methods=['DELETE'])
def remove_container_tag(container_id, host_id, tag_id):
    """Remove a tag from a container"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM container_tags WHERE container_id = ? AND host_id = ? AND tag_id = ?',
            (container_id, host_id, tag_id)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to remove container tag: {e}")
        return jsonify({'error': 'Failed to remove tag from container. Please try again.'}), 500

@app.route('/api/containers/<container_id>/<int:host_id>/webui', methods=['GET'])
@login_required
def get_container_webui(container_id, host_id):
    """Get Web UI URL for a container"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT url FROM container_webui_urls WHERE container_id = ? AND host_id = ?',
            (container_id, host_id)
        )
        result = cursor.fetchone()
        conn.close()
        return jsonify({'url': result[0] if result else None})
    except Exception as e:
        logger.error(f"Failed to get container Web UI URL: {e}")
        return jsonify({'error': 'Failed to load Web UI URL.'}), 500

@app.route('/api/containers/<container_id>/<int:host_id>/webui', methods=['POST'])
@login_required
def set_container_webui(container_id, host_id):
    """Set Web UI URL for a container"""
    try:
        data = request.json
        url = data.get('url', '').strip()

        conn = get_db()
        cursor = conn.cursor()

        if url:
            # Insert or update
            cursor.execute('''
                INSERT INTO container_webui_urls (container_id, host_id, url, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(container_id, host_id) DO UPDATE SET url = ?, updated_at = ?
            ''', (container_id, host_id, url, datetime.now(), url, datetime.now()))
        else:
            # Delete if URL is empty
            cursor.execute(
                'DELETE FROM container_webui_urls WHERE container_id = ? AND host_id = ?',
                (container_id, host_id)
            )

        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to set container Web UI URL: {e}")
        return jsonify({'error': 'Failed to save Web UI URL. Please try again.'}), 500

@app.route('/settings')
@login_required
def settings_page():
    """Settings page"""
    webhook_url = get_setting('discord_webhook_url', '')
    return render_template('settings.html', discord_webhook_url=webhook_url, version=VERSION)

@app.route('/metrics')
@login_required
def metrics_page():
    """Host metrics dashboard page"""
    dark_mode = request.cookies.get('darkMode', 'false') == 'true'
    return render_template('metrics.html', dark_mode=dark_mode, csrf_token=generate_csrf())

@app.route('/hosts')
@login_required
def hosts_page():
    """Redirect to unified settings page (hosts tab)"""
    return redirect('/settings#hosts')

@app.route('/logs')
@login_required
def logs():
    """View logs page"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
    logs = cursor.fetchall()
    conn.close()
    return render_template('logs.html', logs=logs, version=VERSION)

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt  # Login page doesn't have CSRF token yet
@limiter.limit("10 per minute")  # Stricter rate limit for login to prevent brute force
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = sanitize_string(request.form.get('username', ''), max_length=50).strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html', version=VERSION)

        # Get user from database
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password_hash, role FROM users WHERE username = ?', (username,))
            user_data = cursor.fetchone()

            if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
                # Update last login
                cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user_data[0]))
                conn.commit()
                conn.close()

                # Create user object and log in
                user = User(id=user_data[0], username=user_data[1], role=user_data[3])
                login_user(user)
                logger.info(f"User {username} logged in")

                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                conn.close()
                flash('Invalid username or password', 'error')
                return render_template('login.html', version=VERSION)

        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login', 'error')
            return render_template('login.html', version=VERSION)

    return render_template('login.html', version=VERSION)

@app.route('/logout')
@login_required
def logout():
    """Logout"""
    username = current_user.username
    logout_user()
    logger.info(f"User {username} logged out")
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/user-settings')
@login_required
def user_settings_page():
    """Redirect to unified settings page (account tab)"""
    return redirect('/settings#account')

@app.route('/health')
def health_check():
    """Health check endpoint for container orchestration and monitoring"""
    health = {
        'status': 'healthy',
        'version': VERSION,
        'checks': {}
    }

    # Check database connectivity
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=5)
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        health['checks']['database'] = {'status': 'ok'}
    except Exception as e:
        health['status'] = 'unhealthy'
        health['checks']['database'] = {'status': 'error', 'message': str(e)}

    # Check scheduler status
    try:
        if scheduler.running:
            health['checks']['scheduler'] = {'status': 'ok', 'jobs': len(scheduler.get_jobs())}
        else:
            health['status'] = 'unhealthy'
            health['checks']['scheduler'] = {'status': 'error', 'message': 'Scheduler not running'}
    except Exception as e:
        health['status'] = 'degraded'
        health['checks']['scheduler'] = {'status': 'error', 'message': str(e)}

    # Check at least one Docker host is reachable
    try:
        clients = docker_manager.get_all_clients()
        if clients:
            health['checks']['docker'] = {'status': 'ok', 'hosts_connected': len(clients)}
        else:
            health['status'] = 'degraded'
            health['checks']['docker'] = {'status': 'warning', 'message': 'No Docker hosts connected'}
    except Exception as e:
        health['status'] = 'degraded'
        health['checks']['docker'] = {'status': 'error', 'message': str(e)}

    status_code = 200 if health['status'] == 'healthy' else 503 if health['status'] == 'unhealthy' else 200
    return jsonify(health), status_code


@app.route('/api/version')
def get_version():
    """Get application version and build info"""
    import sys

    # Count schedules and hosts
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM schedules WHERE enabled = 1')
        active_schedules = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM hosts WHERE enabled = 1')
        active_hosts = cursor.fetchone()[0]
        conn.close()
    except:
        active_schedules = 0
        active_hosts = 0

    return jsonify({
        'version': VERSION,
        'python_version': sys.version.split()[0],
        'api_version': 'v1',
        'active_schedules': active_schedules,
        'active_hosts': active_hosts
    })


@app.route('/api/user/change-password', methods=['POST'])
@login_required
def change_password():
    """Change current user's password"""
    try:
        data = request.json
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')

        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            return jsonify({'error': 'All fields are required'}), 400

        if new_password != confirm_password:
            return jsonify({'error': 'New passwords do not match'}), 400

        if len(new_password) < 6:
            return jsonify({'error': 'New password must be at least 6 characters'}), 400

        # Verify current password
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,))
        result = cursor.fetchone()

        if not result:
            conn.close()
            return jsonify({'error': 'User not found'}), 404

        if not bcrypt.checkpw(current_password.encode('utf-8'), result[0].encode('utf-8')):
            conn.close()
            return jsonify({'error': 'Current password is incorrect'}), 400

        # Update password
        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_hash.decode('utf-8'), current_user.id)
        )
        conn.commit()
        conn.close()

        logger.info(f"User {current_user.username} changed their password")
        return jsonify({'success': True, 'message': 'Password changed successfully'})

    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({'error': 'Failed to change password'}), 500

if __name__ == '__main__':
    # Create data directory if it doesn't exist
    os.makedirs('/data', exist_ok=True)
    
    # Initialize database
    init_db()
    
    # Load existing schedules
    load_schedules()
    
    # Run Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
