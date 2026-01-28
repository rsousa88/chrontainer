"""
Chrontainer - Docker Container Scheduler
Main Flask application
"""
import os
import time
import concurrent.futures
import docker
import sqlite3
import bcrypt
import secrets
import hashlib
import hmac
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_required, current_user
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
from typing import Tuple, Optional, List, Dict, Any

from app.config import Config
from app.db import ensure_data_dir, get_db, init_db
from app.repositories import (
    ApiKeyRepository,
    AppLogRepository,
    ContainerTagRepository,
    HostRepository,
    HostMetricsRepository,
    LoginRepository,
    LogsRepository,
    ScheduleRepository,
    ScheduleViewRepository,
    SettingsRepository,
    StatsRepository,
    TagRepository,
    UpdateStatusRepository,
    WebuiUrlRepository,
    WebhookRepository,
    UserRepository,
)
from app.routes import (
    create_api_keys_blueprint,
    create_auth_blueprint,
    create_containers_blueprint,
    create_health_blueprint,
    create_hosts_blueprint,
    create_images_blueprint,
    create_logs_blueprint,
    create_schedules_blueprint,
    create_settings_blueprint,
    create_tags_blueprint,
    create_webhooks_blueprint,
)
from app.services.docker_hosts import DockerHostManager
from app.utils.validators import (
    sanitize_string,
    validate_action,
    validate_color,
    validate_container_id,
    validate_container_name,
    validate_cron_expression,
    validate_host_id,
    validate_required_fields,
    validate_url,
    validate_webhook_url,
)

# Load environment variables
load_dotenv()

# Version
VERSION = "0.4.15"

HOST_METRICS_CACHE = {}
HOST_METRICS_CACHE_TTL_SECONDS = 20
CONTAINER_STATS_CACHE = {}
CONTAINER_STATS_CACHE_TTL_SECONDS = 10
DISK_USAGE_CACHE = {}
DISK_USAGE_CACHE_TTL_SECONDS = 300
DISK_USAGE_INFLIGHT = set()
DISK_USAGE_INFLIGHT_LOCK = threading.Lock()
IMAGE_USAGE_CACHE = {}
IMAGE_USAGE_CACHE_TTL_SECONDS = 180
IMAGE_USAGE_INFLIGHT = set()
IMAGE_USAGE_INFLIGHT_LOCK = threading.Lock()
UPDATE_STATUS_CACHE = {}
UPDATE_STATUS_CACHE_TTL_SECONDS = 3600

# Global lock for all cache operations (prevents race conditions)
_cache_lock = threading.RLock()

# Performance limits
MAX_CONCURRENT_STATS_FETCH = 4
BULK_STATS_TIMEOUT_SECONDS = 10
DOCKER_OPERATION_TIMEOUT_SECONDS = 30
DEFAULT_PAGE_SIZE = 100
MAX_LOG_ENTRIES = 1000

# Default cron expression for update checks (daily at 3 AM)
UPDATE_CHECK_CRON_DEFAULT = '0 3 * * *'

# Default host color
HOST_DEFAULT_COLOR = '#3498db'


def get_cached_host_metrics(host_id):
    with _cache_lock:
        entry = HOST_METRICS_CACHE.get(host_id)
        if not entry:
            return None
        if time.time() - entry['timestamp'] > HOST_METRICS_CACHE_TTL_SECONDS:
            return None
        return entry['data']


def set_cached_host_metrics(host_id, data):
    with _cache_lock:
        HOST_METRICS_CACHE[host_id] = {'timestamp': time.time(), 'data': data}


def get_cached_container_stats(cache_key):
    with _cache_lock:
        entry = CONTAINER_STATS_CACHE.get(cache_key)
        if not entry:
            return None
        if time.time() - entry['timestamp'] > CONTAINER_STATS_CACHE_TTL_SECONDS:
            return None
        return entry['data']


def set_cached_container_stats(cache_key, data):
    with _cache_lock:
        CONTAINER_STATS_CACHE[cache_key] = {'timestamp': time.time(), 'data': data}


def get_cached_disk_usage(host_id):
    with _cache_lock:
        entry = DISK_USAGE_CACHE.get(host_id)
        if not entry:
            return None
        if time.time() - entry['timestamp'] > DISK_USAGE_CACHE_TTL_SECONDS:
            return None
        return entry['data']


def set_cached_disk_usage(host_id, data):
    with _cache_lock:
        DISK_USAGE_CACHE[host_id] = {'timestamp': time.time(), 'data': data}


def get_cached_update_status(container_id, host_id):
    with _cache_lock:
        entry = UPDATE_STATUS_CACHE.get((container_id, host_id))
        if not entry:
            return None
        if time.time() - entry['timestamp'] > UPDATE_STATUS_CACHE_TTL_SECONDS:
            return None
        return entry['data']


def set_cached_update_status(container_id, host_id, data):
    with _cache_lock:
        UPDATE_STATUS_CACHE[(container_id, host_id)] = {
            'timestamp': time.time(),
            'data': data
        }


def write_update_status(container_id, host_id, payload):
    set_cached_update_status(container_id, host_id, payload)
    try:
        update_status_repo.upsert(
            container_id=container_id,
            host_id=host_id,
            has_update=bool(payload.get('has_update')),
            remote_digest=payload.get('remote_digest'),
            error=payload.get('error'),
            note=payload.get('note'),
            checked_at=payload.get('checked_at'),
        )
    except Exception as error:
        logger.warning("Failed to persist update status for %s/%s: %s", host_id, container_id, error)


def load_update_status_map():
    try:
        rows = update_status_repo.list_all()
    except Exception as error:
        logger.warning("Failed to load cached update status: %s", error)
        return {}

    status_map = {}
    for container_id, host_id, has_update, remote_digest, error, note, checked_at in rows:
        status_map[(container_id, host_id)] = {
            'has_update': bool(has_update),
            'remote_digest': remote_digest,
            'error': error,
            'note': note,
            'checked_at': checked_at
        }
    return status_map

def refresh_disk_usage_async(host_id, docker_client):
    def run():
        try:
            disk = docker_client.api.df()
            if disk:
                set_cached_disk_usage(host_id, disk)
                logger.info(
                    "Disk usage async cached for host %s: images=%s containers=%s volumes=%s cache=%s layers=%s",
                    host_id,
                    len(disk.get('Images', []) or []),
                    len(disk.get('Containers', []) or []),
                    len(disk.get('Volumes', []) or []),
                    len(disk.get('BuildCache', []) or []),
                    disk.get('LayersSize')
                )
        except Exception as error:
            logger.warning("Disk usage async df failed for host %s: %s", host_id, error)
        finally:
            with DISK_USAGE_INFLIGHT_LOCK:
                DISK_USAGE_INFLIGHT.discard(host_id)

    with DISK_USAGE_INFLIGHT_LOCK:
        if host_id in DISK_USAGE_INFLIGHT:
            return
        DISK_USAGE_INFLIGHT.add(host_id)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()

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

HOST_DEFAULT_COLOR = '#e8f4f8'
UPDATE_CHECK_CRON_DEFAULT = '*/30 * * * *'

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

def split_image_reference(image_ref: str) -> Tuple[str, str]:
    """Split an image reference into repository and tag (if present)."""
    if not image_ref:
        return '', ''

    base = image_ref.split('@', 1)[0]
    if ':' in base:
        repo, candidate = base.rsplit(':', 1)
        if '/' not in candidate:
            return repo, candidate

    repository = base or '(none)'
    return repository, '(none)'

def extract_repository_from_digest(digest: str) -> str:
    """Extract repository from a repo digest entry."""
    if not digest:
        return ''
    base = digest.split('@', 1)[0]
    return base or ''

def set_cached_image_usage(host_id: int, data: Dict[str, Any]) -> None:
    """Cache image usage data for a host."""
    with _cache_lock:
        IMAGE_USAGE_CACHE[host_id] = {
            'data': data,
            'timestamp': time.time()
        }

def get_cached_image_usage(host_id: int) -> Optional[Dict[str, Any]]:
    """Return cached image usage data if fresh."""
    with _cache_lock:
        cached = IMAGE_USAGE_CACHE.get(host_id)
        if not cached:
            return None
        if time.time() - cached['timestamp'] > IMAGE_USAGE_CACHE_TTL_SECONDS:
            return None
        return cached['data']

def refresh_image_usage_async(host_id: int, client: docker.DockerClient, host_name: str) -> None:
    """Fetch image usage data in background to avoid blocking page loads."""
    def run():
        try:
            df_data = client.df()
            set_cached_image_usage(host_id, df_data)
            logger.info(
                "Image usage cached for host %s: images=%s",
                host_name,
                len(df_data.get('Images', []) or [])
            )
        except Exception as error:
            logger.warning("Image usage df failed for host %s: %s", host_name, error)
        finally:
            with IMAGE_USAGE_INFLIGHT_LOCK:
                IMAGE_USAGE_INFLIGHT.discard(host_id)

    with IMAGE_USAGE_INFLIGHT_LOCK:
        if host_id in IMAGE_USAGE_INFLIGHT:
            return
        IMAGE_USAGE_INFLIGHT.add(host_id)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()

def clear_image_usage_cache() -> None:
    """Clear cached image usage data."""
    with _cache_lock:
        IMAGE_USAGE_CACHE.clear()

 

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path configuration
DATABASE_PATH = Config.DATABASE_PATH

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
        user_data = user_repo.get_by_id(user_id)

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

def generate_api_key():
    """Generate a new API key"""
    key_body = secrets.token_urlsafe(22)[:30]
    return f"chron_{key_body}"

def hash_api_key(key):
    """Hash an API key for storage"""
    return hashlib.sha256(key.encode()).hexdigest()

def verify_api_key(key, key_hash):
    """Verify an API key against its hash using constant-time comparison"""
    computed_hash = hash_api_key(key)
    return hmac.compare_digest(computed_hash, key_hash)

def api_key_or_login_required(f):
    """Allow either session auth or API key auth"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key:
            if not api_key.startswith('chron_'):
                return jsonify({'error': 'Invalid API key format'}), 401

            key_hash = hash_api_key(api_key)
            result = api_key_repo.get_auth_record(key_hash)
            if not result:
                return jsonify({'error': 'Invalid API key'}), 401

            key_id, user_id, permissions, expires_at, user_role = result

            if expires_at:
                try:
                    expires_dt = datetime.fromisoformat(expires_at)
                    if expires_dt < datetime.now():
                        return jsonify({'error': 'API key expired'}), 401
                except ValueError as e:
                    logger.error(f"Invalid datetime format in API key {key_id} expiry: {expires_at} - {e}")
                    return jsonify({'error': 'Invalid API key expiry'}), 401

            api_key_repo.touch_last_used(key_id)

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

# Initialize Docker host manager
host_repo = HostRepository(get_db)
docker_manager = DockerHostManager(host_repo)
settings_repo = SettingsRepository(get_db)
logs_repo = LogsRepository(get_db)
update_status_repo = UpdateStatusRepository(get_db)
schedule_repo = ScheduleRepository(get_db)
tag_repo = TagRepository(get_db)
container_tag_repo = ContainerTagRepository(get_db)
webui_url_repo = WebuiUrlRepository(get_db)
user_repo = UserRepository(get_db)
api_key_repo = ApiKeyRepository(get_db)
webhook_repo = WebhookRepository(get_db)
app_log_repo = AppLogRepository(get_db)
schedule_view_repo = ScheduleViewRepository(get_db)
host_metrics_repo = HostMetricsRepository(get_db)
login_repo = LoginRepository(get_db)
stats_repo = StatsRepository(get_db)

health_blueprint = create_health_blueprint(
    stats_repo=stats_repo,
    docker_manager=docker_manager,
    scheduler=scheduler,
    db_factory=get_db,
    version=VERSION,
)
app.register_blueprint(health_blueprint)

auth_blueprint = create_auth_blueprint(
    login_repo=login_repo,
    user_class=User,
    limiter=limiter,
    csrf=csrf,
    version=VERSION,
    logger=logger,
)
app.register_blueprint(auth_blueprint)

logs_blueprint = create_logs_blueprint(app_log_repo=app_log_repo, version=VERSION)
app.register_blueprint(logs_blueprint)

settings_blueprint = create_settings_blueprint(
    get_setting=get_setting,
    set_setting=set_setting,
    configure_update_check_schedule=configure_update_check_schedule,
    send_discord_notification=send_discord_notification,
    sanitize_string=sanitize_string,
    validate_cron_expression=validate_cron_expression,
    validate_webhook_url=validate_webhook_url,
    logger=logger,
    update_check_cron_default=UPDATE_CHECK_CRON_DEFAULT,
    version=VERSION,
)
app.register_blueprint(settings_blueprint)

api_keys_blueprint = create_api_keys_blueprint(
    api_key_repo=api_key_repo,
    generate_api_key=generate_api_key,
    hash_api_key=hash_api_key,
    sanitize_string=sanitize_string,
    logger=logger,
)
app.register_blueprint(api_keys_blueprint)

webhooks_blueprint = create_webhooks_blueprint(
    webhook_repo=webhook_repo,
    docker_manager=docker_manager,
    limiter=limiter,
    restart_container=restart_container,
    start_container=start_container,
    stop_container=stop_container,
    pause_container=pause_container,
    unpause_container=unpause_container,
    update_container=update_container,
    sanitize_string=sanitize_string,
    logger=logger,
)
app.register_blueprint(webhooks_blueprint)

images_blueprint = create_images_blueprint(
    api_key_or_login_required=api_key_or_login_required,
    clear_image_usage_cache=clear_image_usage_cache,
    fetch_all_images=fetch_all_images,
    docker_manager=docker_manager,
    host_repo=host_repo,
    sanitize_string=sanitize_string,
    validate_host_id=validate_host_id,
    logger=logger,
    version=VERSION,
)
app.register_blueprint(images_blueprint)

hosts_blueprint = create_hosts_blueprint(
    api_key_or_login_required=api_key_or_login_required,
    docker_manager=docker_manager,
    host_metrics_repo=host_metrics_repo,
    host_repo=host_repo,
    get_cached_host_metrics=get_cached_host_metrics,
    set_cached_host_metrics=set_cached_host_metrics,
    sanitize_string=sanitize_string,
    schedule_repo=schedule_repo,
    validate_color=validate_color,
    validate_host_id=validate_host_id,
    validate_required_fields=validate_required_fields,
    validate_url=validate_url,
    host_default_color=HOST_DEFAULT_COLOR,
    datetime_factory=datetime.now,
    sqlite3_module=sqlite3,
    logger=logger,
)
app.register_blueprint(hosts_blueprint)

containers_blueprint = create_containers_blueprint(
    api_key_or_login_required=api_key_or_login_required,
    docker_manager=docker_manager,
    fetch_all_containers=fetch_all_containers,
    get_cached_container_stats=get_cached_container_stats,
    set_cached_container_stats=set_cached_container_stats,
    logger=logger,
    restart_container=restart_container,
    start_container=start_container,
    stop_container=stop_container,
    pause_container=pause_container,
    unpause_container=unpause_container,
    update_container=update_container,
    delete_container=delete_container,
    rename_container=rename_container,
    clone_container=clone_container,
    check_for_update=check_for_update,
    write_update_status=write_update_status,
    validate_container_id=validate_container_id,
    validate_container_name=validate_container_name,
    validate_host_id=validate_host_id,
    sanitize_string=sanitize_string,
    container_tag_repo=container_tag_repo,
    webui_url_repo=webui_url_repo,
    schedule_view_repo=schedule_view_repo,
    version=VERSION,
)
app.register_blueprint(containers_blueprint)

schedules_blueprint = create_schedules_blueprint(
    api_key_or_login_required=api_key_or_login_required,
    schedule_repo=schedule_repo,
    scheduler=scheduler,
    restart_container=restart_container,
    start_container=start_container,
    stop_container=stop_container,
    pause_container=pause_container,
    unpause_container=unpause_container,
    update_container=update_container,
    validate_action=validate_action,
    validate_container_id=validate_container_id,
    validate_container_name=validate_container_name,
    validate_cron_expression=validate_cron_expression,
    validate_host_id=validate_host_id,
    sanitize_string=sanitize_string,
    logger=logger,
)
app.register_blueprint(schedules_blueprint)

tags_blueprint = create_tags_blueprint(
    api_key_or_login_required=api_key_or_login_required,
    tag_repo=tag_repo,
    sanitize_string=sanitize_string,
    validate_color=validate_color,
    host_default_color=HOST_DEFAULT_COLOR,
    sqlite3_module=sqlite3,
    logger=logger,
)
app.register_blueprint(tags_blueprint)

# Container update management functions
def check_for_update(container, client) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """
    Check if a container has an update available.

    Args:
        container: Docker container object
        client: Docker client instance

    Returns:
        Tuple of (has_update, remote_digest, error, note):
        - has_update (bool): True if update is available
        - remote_digest (Optional[str]): Remote image digest if available
        - error (Optional[str]): Error message if check failed
        - note (Optional[str]): Informational message (e.g., missing digest)
    """
    try:
        # Get the image used by the container
        image_name = container.image.tags[0] if container.image.tags else container.attrs.get('Config', {}).get('Image', '')

        if not image_name or ':' not in image_name:
            return False, None, "Unable to determine image tag", None

        # Get local image digest
        local_image = container.image
        local_digest = local_image.attrs.get('RepoDigests', [])
        if not local_digest:
            return False, None, None, "No local digest"
        local_digest = local_digest[0].split('@')[1] if '@' in local_digest[0] else None

        try:
            # Get registry data for the image
            registry_data = client.images.get_registry_data(image_name)
            remote_digest = registry_data.attrs.get('Descriptor', {}).get('digest')

            if not remote_digest or not local_digest:
                return False, None, None, "Digest missing"

            # Compare digests
            has_update = (remote_digest != local_digest)
            return has_update, remote_digest, None, None

        except docker.errors.APIError as e:
            # Handle rate limits, authentication errors, etc.
            message = str(e)
            if 'distribution' in message and 'Forbidden' in message:
                return False, None, f"Registry error: socket-proxy forbids distribution endpoint. Enable DISTRIBUTION=1.", None
            return False, None, f"Registry error: {message}", None

    except Exception as e:
        logger.error(f"Error checking for update: {e}")
        return False, None, str(e), None


def run_update_check_job():
    """System job that refreshes update status for all containers."""
    try:
        for host_id, host_name, docker_client in docker_manager.get_all_clients():
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers:
                    container_id = container.id[:12]
                    has_update, remote_digest, error, note = check_for_update(container, docker_client)
                    payload = {
                        'has_update': has_update,
                        'remote_digest': remote_digest,
                        'error': error,
                        'note': note,
                        'checked_at': datetime.utcnow().isoformat()
                    }
                    write_update_status(container_id, host_id, payload)
            except Exception as error:
                logger.error(f"Scheduled update check failed for host {host_name}: {error}")
        logger.info("Scheduled update check completed")
    except Exception as error:
        logger.error(f"Scheduled update check failed: {error}")


def configure_update_check_schedule():
    """Configure or disable the system update-check job."""
    job_id = 'system_update_check'
    try:
        scheduler.remove_job(job_id)
    except Exception as e:
        logger.debug(f"Could not remove job {job_id} (may not exist): {e}")

    enabled_setting = get_setting('update_check_enabled', 'true').lower()
    cron_expression = get_setting('update_check_cron', UPDATE_CHECK_CRON_DEFAULT)
    enabled = enabled_setting == 'true'

    if not enabled:
        return

    valid, error = validate_cron_expression(cron_expression)
    if not valid:
        logger.warning("Invalid update-check cron expression %s: %s", cron_expression, error)
        return

    parts = cron_expression.split()
    trigger = CronTrigger(
        minute=parts[0],
        hour=parts[1],
        day=parts[2],
        month=parts[3],
        day_of_week=parts[4]
    )
    scheduler.add_job(run_update_check_job, trigger, id=job_id, replace_existing=True)

def update_container(container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> Tuple[bool, str]:
    """
    Update a container by pulling the latest image and recreating it.

    Performs a container update by:
    1. Pulling the latest version of the container's image
    2. Stopping and removing the current container
    3. Creating a new container with the same configuration
    4. Preserving volumes, ports, environment variables, labels, and restart policy

    Logs the action to the database and sends notifications via configured channels.
    Updates the schedule's last_run timestamp if executed as part of a schedule.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Human-readable container name for logging
        schedule_id: Schedule ID that triggered this action (None if manual)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if update successful, False otherwise
        - message: Description of the result or error

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        This operation requires the container to be recreated, which means a brief
        downtime. All container configuration is preserved from the original container.
    """
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
        update_schedule_last_run(schedule_id)

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

def resolve_container(docker_client, container_id, container_name=None):
    try:
        return docker_client.containers.get(container_id), False
    except docker.errors.NotFound:
        logger.debug(f"Container {container_id} not found by ID, will try by name")
    except Exception as e:
        logger.warning(f"Error getting container by ID {container_id}: {e}")

    if not container_name:
        return None, False

    try:
        matches = docker_client.containers.list(all=True, filters={'name': container_name}) or []
        for candidate in matches:
            if candidate.name == container_name:
                return candidate, True
        if len(matches) == 1:
            return matches[0], True
    except Exception as e:
        logger.error(f"Error resolving container by name {container_name}: {e}")

    return None, False

def update_schedule_container_id(schedule_id, container_id):
    if not schedule_id or not container_id:
        return
    try:
        schedule_repo.update_container_id(schedule_id, container_id)
    except Exception as e:
        logger.error(f"Failed to update schedule {schedule_id} container_id to {container_id}: {e}")

def update_schedule_container_name(host_id: int, container_id: str, old_name: str, new_name: str) -> int:
    """Update schedule container_name for a renamed container."""
    try:
        return schedule_repo.update_container_name(host_id, container_id, old_name, new_name)
    except Exception as e:
        logger.error(f"Failed to update schedules for renamed container {old_name}: {e}")
        return 0

def disable_container_schedules(container_id: str, container_name: str, host_id: int) -> int:
    """Disable schedules linked to a container that has been removed."""
    try:
        return schedule_repo.disable_by_container(host_id, container_id, container_name)
    except Exception as e:
        logger.error(f"Failed to disable schedules for container {container_name}: {e}")
        return 0

def restart_container(container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> Tuple[bool, str]:
    """
    Restart a Docker container and log the action.

    Restarts the specified container on the given Docker host. Logs the action to
    the database and sends notifications via configured channels (Discord, ntfy).
    Updates the schedule's last_run timestamp if executed as part of a schedule.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Human-readable container name for logging
        schedule_id: Schedule ID that triggered this action (None if manual)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if restart successful, False otherwise
        - message: Description of the result or error

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        If the container is resolved by name (not ID), the schedule's container_id
        is updated to the actual container ID for future executions.
    """
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, resolved_by_name = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")
        container.restart()
        if resolved_by_name:
            update_schedule_container_id(schedule_id, container.id[:12])
        message = f"Container {container_name} restarted successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'restart', 'success', message, host_id)
        send_discord_notification(container_name, 'restart', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'restart', 'success', message, schedule_id)

        # Update last_run in schedules
        update_schedule_last_run(schedule_id)

        return True, message
    except Exception as e:
        message = f"Failed to restart container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'restart', 'error', message, host_id)
        send_discord_notification(container_name, 'restart', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'restart', 'error', message, schedule_id)
        return False, message

def start_container(container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> Tuple[bool, str]:
    """
    Start a Docker container and log the action.

    Starts the specified container on the given Docker host. Logs the action to
    the database and sends notifications via configured channels (Discord, ntfy).
    Updates the schedule's last_run timestamp if executed as part of a schedule.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Human-readable container name for logging
        schedule_id: Schedule ID that triggered this action (None if manual)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if start successful, False otherwise
        - message: Description of the result or error

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        If the container is resolved by name (not ID), the schedule's container_id
        is updated to the actual container ID for future executions.
    """
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, resolved_by_name = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")
        container.start()
        if resolved_by_name:
            update_schedule_container_id(schedule_id, container.id[:12])
        message = f"Container {container_name} started successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'start', 'success', message, host_id)
        send_discord_notification(container_name, 'start', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'start', 'success', message, schedule_id)

        # Update last_run in schedules
        update_schedule_last_run(schedule_id)

        return True, message
    except Exception as e:
        message = f"Failed to start container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'start', 'error', message, host_id)
        send_discord_notification(container_name, 'start', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'start', 'error', message, schedule_id)
        return False, message

def stop_container(container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> Tuple[bool, str]:
    """
    Stop a Docker container and log the action.

    Stops the specified container on the given Docker host. Logs the action to
    the database and sends notifications via configured channels (Discord, ntfy).
    Updates the schedule's last_run timestamp if executed as part of a schedule.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Human-readable container name for logging
        schedule_id: Schedule ID that triggered this action (None if manual)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if stop successful, False otherwise
        - message: Description of the result or error

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        If the container is resolved by name (not ID), the schedule's container_id
        is updated to the actual container ID for future executions.
    """
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, resolved_by_name = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")
        container.stop()
        if resolved_by_name:
            update_schedule_container_id(schedule_id, container.id[:12])
        message = f"Container {container_name} stopped successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'stop', 'success', message, host_id)
        send_discord_notification(container_name, 'stop', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'stop', 'success', message, schedule_id)

        # Update last_run in schedules
        update_schedule_last_run(schedule_id)

        return True, message
    except Exception as e:
        message = f"Failed to stop container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'stop', 'error', message, host_id)
        send_discord_notification(container_name, 'stop', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'stop', 'error', message, schedule_id)
        return False, message

def delete_container(container_id: str, container_name: str, remove_volumes: bool = False, force: bool = False, host_id: int = 1) -> Tuple[bool, str]:
    """
    Delete a Docker container and log the action.

    Removes the specified container on the given Docker host. Optionally removes
    associated volumes. If the container is running and force is False, it will
    be stopped before removal. Any schedules linked to the container are automatically
    disabled to prevent future failures.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Human-readable container name for logging
        remove_volumes: If True, remove associated volumes (default: False)
        force: If True, force removal without stopping first (default: False)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if deletion successful, False otherwise
        - message: Description of the result, including number of schedules disabled

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Warning:
        This is a destructive operation. The container and optionally its volumes
        will be permanently removed. Any schedules associated with this container
        will be disabled automatically.

    Note:
        Running containers will be stopped first unless force=True is specified.
    """
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, _ = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")

        container.reload()
        if container.status == 'running' and not force:
            container.stop()

        container.remove(v=remove_volumes, force=force)

        disabled = disable_container_schedules(container.id, container_name, host_id)

        message = f"Container {container_name} deleted successfully"
        if remove_volumes:
            message += " (volumes removed)"
        if disabled:
            message += f"; disabled {disabled} schedule(s)"

        logger.info(message)
        log_action(None, container_name, 'delete', 'success', message, host_id)
        send_discord_notification(container_name, 'delete', 'success', message, None)
        send_ntfy_notification(container_name, 'delete', 'success', message, None)

        return True, message
    except Exception as e:
        message = f"Failed to delete container {container_name}: {str(e)}"
        logger.error(message)
        log_action(None, container_name, 'delete', 'error', message, host_id)
        send_discord_notification(container_name, 'delete', 'error', message, None)
        send_ntfy_notification(container_name, 'delete', 'error', message, None)
        return False, message

def rename_container(container_id: str, container_name: str, new_name: str, host_id: int = 1) -> Tuple[bool, str]:
    """
    Rename a Docker container and update related schedules.

    Renames the specified container on the given Docker host. Automatically updates
    all schedules that reference this container (by ID or name) to use the new name.
    Logs the action to the database and sends notifications via configured channels.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Current container name
        new_name: New container name to assign
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if rename successful, False otherwise
        - message: Description of the result, including number of schedules updated

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        This operation updates all schedules that reference the container, ensuring
        scheduled actions continue to work after the rename.
    """
    try:
        # Validate new container name
        is_valid, error_msg = validate_container_name(new_name)
        if not is_valid:
            return False, error_msg

        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, _ = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")

        container.rename(new_name)
        updated = update_schedule_container_name(host_id, container.id, container_name, new_name)

        message = f"Container {container_name} renamed to {new_name}"
        if updated:
            message += f"; updated {updated} schedule(s)"

        logger.info(message)
        log_action(None, container_name, 'rename', 'success', message, host_id)
        send_discord_notification(container_name, 'rename', 'success', message, None)
        send_ntfy_notification(container_name, 'rename', 'success', message, None)

        return True, message
    except Exception as e:
        message = f"Failed to rename container {container_name}: {str(e)}"
        logger.error(message)
        log_action(None, container_name, 'rename', 'error', message, host_id)
        send_discord_notification(container_name, 'rename', 'error', message, None)
        send_ntfy_notification(container_name, 'rename', 'error', message, None)
        return False, message

def clone_container(container_id: str, container_name: str, new_name: str, start_after: bool = True, host_id: int = 1) -> Tuple[bool, str]:
    """
    Clone a Docker container with a new name and identical configuration.

    Creates a new container on the given Docker host by copying the configuration
    of an existing container. Preserves all settings including:
    - Image and tag
    - Environment variables
    - Volume binds and mounts
    - Port bindings and exposed ports
    - Restart policy
    - Network mode
    - Privileges and capabilities
    - Labels and metadata
    - Working directory and user

    The new container is created with the same configuration but a different name.
    Optionally starts the new container immediately after creation.

    Args:
        container_id: Source container ID (12 or 64 hex characters)
        container_name: Source container name for logging
        new_name: Name for the cloned container
        start_after: If True, start the cloned container after creation (default: True)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if clone successful, False otherwise
        - message: Description of the result

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        Volume data is NOT copied - the cloned container will have empty volumes or
        share the same volume mounts as the source container depending on volume type.
        The source container does not need to be running to be cloned.
    """
    try:
        # Validate new container name
        is_valid, error_msg = validate_container_name(new_name)
        if not is_valid:
            return False, error_msg

        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, _ = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")

        container.reload()
        attrs = container.attrs or {}
        config = attrs.get('Config', {}) or {}
        host_config = attrs.get('HostConfig', {}) or {}

        image = (container.image.tags[0] if container.image.tags else config.get('Image'))
        if not image:
            raise Exception("Source image not available for clone")

        exposed_ports = config.get('ExposedPorts') or {}
        port_bindings = host_config.get('PortBindings') or None

        new_host_config = docker.types.HostConfig(
            binds=host_config.get('Binds'),
            port_bindings=port_bindings,
            restart_policy=host_config.get('RestartPolicy'),
            network_mode=host_config.get('NetworkMode'),
            privileged=host_config.get('Privileged', False),
            cap_add=host_config.get('CapAdd'),
            cap_drop=host_config.get('CapDrop'),
            extra_hosts=host_config.get('ExtraHosts'),
            devices=host_config.get('Devices')
        )

        create_kwargs = {
            'image': image,
            'name': new_name,
            'command': config.get('Cmd'),
            'environment': config.get('Env'),
            'labels': config.get('Labels'),
            'entrypoint': config.get('Entrypoint'),
            'working_dir': config.get('WorkingDir'),
            'user': config.get('User'),
            'hostname': config.get('Hostname'),
            'domainname': config.get('Domainname'),
            'host_config': new_host_config
        }

        if exposed_ports:
            create_kwargs['ports'] = list(exposed_ports.keys())

        new_container = docker_client.api.create_container(**create_kwargs)
        new_container_id = new_container.get('Id')

        if start_after:
            docker_client.api.start(new_container_id)

        message = f"Container {container_name} cloned to {new_name}"
        logger.info(message)
        log_action(None, container_name, 'clone', 'success', message, host_id)
        send_discord_notification(container_name, 'clone', 'success', message, None)
        send_ntfy_notification(container_name, 'clone', 'success', message, None)

        return True, message
    except Exception as e:
        message = f"Failed to clone container {container_name}: {str(e)}"
        logger.error(message)
        log_action(None, container_name, 'clone', 'error', message, host_id)
        send_discord_notification(container_name, 'clone', 'error', message, None)
        send_ntfy_notification(container_name, 'clone', 'error', message, None)
        return False, message

def pause_container(container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> Tuple[bool, str]:
    """
    Pause a Docker container and log the action.

    Pauses the specified container on the given Docker host (freezes all processes).
    Logs the action to the database and sends notifications via configured channels.
    Updates the schedule's last_run timestamp if executed as part of a schedule.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Human-readable container name for logging
        schedule_id: Schedule ID that triggered this action (None if manual)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if pause successful, False otherwise
        - message: Description of the result or error

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        If the container is resolved by name (not ID), the schedule's container_id
        is updated to the actual container ID for future executions.
    """
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, resolved_by_name = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")
        container.pause()
        if resolved_by_name:
            update_schedule_container_id(schedule_id, container.id[:12])
        message = f"Container {container_name} paused successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'pause', 'success', message, host_id)
        send_discord_notification(container_name, 'pause', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'pause', 'success', message, schedule_id)

        # Update last_run in schedules
        update_schedule_last_run(schedule_id)

        return True, message
    except Exception as e:
        message = f"Failed to pause container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'pause', 'error', message, host_id)
        send_discord_notification(container_name, 'pause', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'pause', 'error', message, schedule_id)
        return False, message

def unpause_container(container_id: str, container_name: str, schedule_id: Optional[int] = None, host_id: int = 1) -> Tuple[bool, str]:
    """
    Unpause a Docker container and log the action.

    Unpauses the specified container on the given Docker host (resumes frozen processes).
    Logs the action to the database and sends notifications via configured channels.
    Updates the schedule's last_run timestamp if executed as part of a schedule.

    Args:
        container_id: Docker container ID (12 or 64 hex characters)
        container_name: Human-readable container name for logging
        schedule_id: Schedule ID that triggered this action (None if manual)
        host_id: Docker host ID from hosts table (default: 1 for local)

    Returns:
        Tuple of (success: bool, message: str)
        - success: True if unpause successful, False otherwise
        - message: Description of the result or error

    Raises:
        None - All exceptions are caught and returned as (False, error_message)

    Note:
        If the container is resolved by name (not ID), the schedule's container_id
        is updated to the actual container ID for future executions.
    """
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            raise Exception(f"Cannot connect to Docker host {host_id}")

        container, resolved_by_name = resolve_container(docker_client, container_id, container_name)
        if not container:
            raise docker.errors.NotFound(f"No such container: {container_id}")
        container.unpause()
        if resolved_by_name:
            update_schedule_container_id(schedule_id, container.id[:12])
        message = f"Container {container_name} unpaused successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'unpause', 'success', message, host_id)
        send_discord_notification(container_name, 'unpause', 'success', message, schedule_id)
        send_ntfy_notification(container_name, 'unpause', 'success', message, schedule_id)

        # Update last_run in schedules
        update_schedule_last_run(schedule_id)

        return True, message
    except Exception as e:
        message = f"Failed to unpause container {container_name}: {str(e)}"
        logger.error(message)
        log_action(schedule_id, container_name, 'unpause', 'error', message, host_id)
        send_discord_notification(container_name, 'unpause', 'error', message, schedule_id)
        send_ntfy_notification(container_name, 'unpause', 'error', message, schedule_id)
        return False, message

def log_action(schedule_id: Optional[int], container_name: str, action: str, status: str, message: str, host_id: int = 1) -> None:
    """Log an action to the database"""
    try:
        logs_repo.insert_action_log(
            schedule_id=schedule_id,
            container_name=container_name,
            action=action,
            status=status,
            message=message,
            host_id=host_id,
        )
    except Exception as e:
        logger.error(f"Failed to log action: {e}")


def update_schedule_last_run(schedule_id: Optional[int]) -> None:
    if not schedule_id:
        return
    try:
        schedule_repo.update_last_run(schedule_id, datetime.now())
    except Exception as e:
        logger.error(f"Failed to update schedule {schedule_id} last_run: {e}")

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get a setting value from the database"""
    try:
        value = settings_repo.get(key)
        return value if value is not None else default
    except Exception as e:
        logger.error(f"Failed to get setting {key}: {e}")
        return default

def set_setting(key: str, value: str) -> bool:
    """Set a setting value in the database"""
    try:
        settings_repo.set(key, value)
        return True
    except Exception as e:
        logger.error(f"Failed to set setting {key}: {e}")
        return False

def send_discord_notification(container_name: str, action: str, status: str, message: str, schedule_id: Optional[int] = None) -> None:
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

def send_ntfy_notification(container_name: str, action: str, status: str, message: str, schedule_id: Optional[int] = None) -> None:
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
    schedules = schedule_repo.list_enabled()

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
                        schedule_repo.delete(sid)
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


def fetch_all_containers() -> List[Dict[str, Any]]:
    """
    Fetch all containers from all Docker hosts with enriched metadata.

    Returns:
        List of container dictionaries with tags, webui URLs, and update status.
    """
    container_list = []
    host_color_map, host_text_color_map = get_host_color_maps()

    # Fetch containers from all hosts
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
                    except Exception as e:
                        # Last resort: use short image ID
                        logger.debug(f"Could not get image name from Config for {container.id}: {e}")
                        image_name = container.image.short_id.replace('sha256:', '')[:12]

                # Extract IP addresses from all networks
                ip_addresses = []
                try:
                    networks = container.attrs['NetworkSettings']['Networks']
                    for network_name, network_info in networks.items():
                        if network_info.get('IPAddress'):
                            ip_addresses.append(network_info['IPAddress'])
                except Exception as e:
                    logger.debug(f"Could not extract IP addresses for {container.id}: {e}")

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
                except Exception as e:
                    logger.debug(f"Could not extract labels for {container.id}: {e}")

                # Extract health status if available
                health_status = None
                try:
                    health = container.attrs.get('State', {}).get('Health', {})
                    if health:
                        health_status = health.get('Status')  # healthy, unhealthy, starting, or none
                except Exception as e:
                    logger.debug(f"Could not extract health status for {container.id}: {e}")

                state = container.attrs.get('State', {}) or {}
                status = state.get('Status') or container.status
                exit_code = state.get('ExitCode')
                status_display = status
                status_class = status
                if status == 'exited' and exit_code not in (None, 0):
                    status_display = 'error'
                    status_class = 'error'

                image_display = strip_image_tag(image_name)
                host_color = host_color_map.get(host_id, HOST_DEFAULT_COLOR)
                host_text_color = host_text_color_map.get(host_id, get_contrast_text_color(host_color))

                container_list.append({
                    'id': container.id[:12],
                    'name': container.name,
                    'status': status,
                    'status_display': status_display,
                    'status_class': status_class,
                    'exit_code': exit_code,
                    'health': health_status,
                    'image': image_name,
                    'image_display': image_display,
                    'created': container.attrs.get('Created'),
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
    # Get all tags for containers
    tags_map = {}  # Key: (container_id, host_id), Value: list of tags
    for row in container_tag_repo.list_all():
        key = (row[0], row[1])
        if key not in tags_map:
            tags_map[key] = []
        tags_map[key].append({'id': row[2], 'name': row[3], 'color': row[4]})

    # Get all manual webui URLs
    webui_map = {}  # Key: (container_id, host_id), Value: url
    for row in webui_url_repo.list_all():
        webui_map[(row[0], row[1])] = row[2]

    # Load update status from cache
    update_status_map = load_update_status_map()

    # Attach tags, webui URLs, image links, and update status to containers
    for container in container_list:
        key = (container['id'], container['host_id'])
        container['tags'] = tags_map.get(key, [])
        # Manual URL takes precedence over label URL
        container['webui_url'] = webui_map.get(key) or container.get('webui_url_label')
        # Generate image registry/GitHub/docs links
        container['image_links'] = get_image_links(container['image'])
        # Attach cached update status
        cached_status = update_status_map.get(key)
        if cached_status:
            container['update_status'] = cached_status

    return container_list

def get_host_color_maps() -> Tuple[Dict[int, str], Dict[int, str]]:
    """Return host background and text colors keyed by host ID."""
    host_color_map = {}
    host_text_color_map = {}

    for host_id_row, color in host_repo.list_colors():
        resolved_color = color or HOST_DEFAULT_COLOR
        host_color_map[host_id_row] = resolved_color
        host_text_color_map[host_id_row] = get_contrast_text_color(resolved_color)

    return host_color_map, host_text_color_map

def fetch_all_images() -> List[Dict[str, Any]]:
    """
    Fetch all images from all Docker hosts with basic metadata.

    Returns:
        List of image dictionaries with host info and tags.
    """
    image_list = []
    host_color_map, host_text_color_map = get_host_color_maps()

    for host_id, host_name, docker_client in docker_manager.get_all_clients():
        df_images = {}
        cached_df = get_cached_image_usage(host_id)
        cached_from_images = cached_df is not None
        if not cached_df:
            cached_df = get_cached_disk_usage(host_id)
        if cached_df:
            df_images = {entry.get('Id'): entry for entry in (cached_df.get('Images', []) or [])}
        if not cached_from_images:
            refresh_image_usage_async(host_id, docker_client, host_name)

        host_color = host_color_map.get(host_id, HOST_DEFAULT_COLOR)
        host_text_color = host_text_color_map.get(host_id, get_contrast_text_color(host_color))

        container_repo_map = {}
        try:
            containers = docker_client.containers.list(all=True)
            for container in containers:
                try:
                    image_id = container.image.id
                    if not image_id:
                        continue
                    image_name = None
                    if container.image.tags:
                        image_name = container.image.tags[0]
                    else:
                        image_name = container.attrs.get('Config', {}).get('Image')
                    if image_name:
                        repo, _ = split_image_reference(image_name)
                        container_repo_map[image_id] = repo or container_repo_map.get(image_id)
                except Exception:
                    continue
        except Exception as e:
            logger.debug("Failed to map container images for host %s: %s", host_name, e)

        if df_images:
            for entry in df_images.values():
                image_id = entry.get('Id') or ''
                short_id = image_id.replace('sha256:', '')[:12]
                created = entry.get('Created')
                size = entry.get('Size')
                shared_size = entry.get('SharedSize')
                containers_count = entry.get('Containers')
                if containers_count is not None and containers_count < 0:
                    containers_count = None
                repo_tags = entry.get('RepoTags') or []
                repo_digests = entry.get('RepoDigests') or []
                if not repo_tags:
                    repo_tags = ['(none):(none)']

                for tag in repo_tags:
                    repository, tag_name = split_image_reference(tag)
                    if repository in ('', '(none)') and repo_digests:
                        digest_repo = extract_repository_from_digest(repo_digests[0])
                        repository = digest_repo or '(none)'
                    if repository in ('', '(none)'):
                        repository = container_repo_map.get(image_id) or repository
                    repository = repository or '(none)'
                    image_list.append({
                        'id': image_id,
                        'short_id': short_id,
                        'image_id': image_id,
                        'repository': repository,
                        'tag': tag_name,
                        'full_name': tag,
                        'size_bytes': size,
                        'shared_size_bytes': shared_size,
                        'containers': containers_count,
                        'created': created,
                        'host_id': host_id,
                        'host_name': host_name,
                        'host_color': host_color,
                        'host_text_color': host_text_color
                    })
            continue

        try:
            images = docker_client.api.images(all=True)
            for entry in images:
                image_id = entry.get('Id') or ''
                short_id = image_id.replace('sha256:', '')[:12]
                created = entry.get('Created')
                size = entry.get('Size')
                shared_size = entry.get('SharedSize')
                containers_count = entry.get('Containers')
                if containers_count is not None and containers_count < 0:
                    containers_count = None
                repo_tags = entry.get('RepoTags') or []
                repo_digests = entry.get('RepoDigests') or []
                if not repo_tags:
                    repo_tags = ['(none):(none)']

                for tag in repo_tags:
                    repository, tag_name = split_image_reference(tag)
                    if repository in ('', '(none)') and repo_digests:
                        digest_repo = extract_repository_from_digest(repo_digests[0])
                        repository = digest_repo or '(none)'
                    if repository in ('', '(none)'):
                        repository = container_repo_map.get(image_id) or repository
                    repository = repository or '(none)'
                    image_list.append({
                        'id': image_id,
                        'short_id': short_id,
                        'image_id': image_id,
                        'repository': repository,
                        'tag': tag_name,
                        'full_name': tag,
                        'size_bytes': size,
                        'shared_size_bytes': shared_size,
                        'containers': containers_count,
                        'created': created,
                        'host_id': host_id,
                        'host_name': host_name,
                        'host_color': host_color,
                        'host_text_color': host_text_color
                    })
        except Exception as e:
            logger.error(f"Error getting images from host {host_name}: {e}")

    return image_list


# ===== Tags API =====

@app.route('/metrics')
@login_required
def metrics_page():
    """Host metrics dashboard page"""
    dark_mode = request.cookies.get('darkMode', 'false') == 'true'
    return render_template('metrics.html', dark_mode=dark_mode)

@app.route('/hosts')
@login_required
def hosts_page():
    """Redirect to unified settings page (hosts tab)"""
    return redirect('/settings#hosts')

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
        password_hash = user_repo.get_password_hash(current_user.id)
        if not password_hash:
            return jsonify({'error': 'User not found'}), 404

        if not bcrypt.checkpw(current_password.encode('utf-8'), password_hash.encode('utf-8')):
            return jsonify({'error': 'Current password is incorrect'}), 400

        # Update password
        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user_repo.update_password(current_user.id, new_hash.decode('utf-8'))

        logger.info(f"User {current_user.username} changed their password")
        return jsonify({'success': True, 'message': 'Password changed successfully'})

    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({'error': 'Failed to change password'}), 500

if __name__ == '__main__':
    try:
        ensure_data_dir()
    except OSError as exc:
        logger.warning("Failed to ensure database directory %s", exc)
    
    # Initialize database
    init_db()
    
    # Load existing schedules
    load_schedules()

    # Configure update-check schedule
    configure_update_check_schedule()
    
    # Run Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
