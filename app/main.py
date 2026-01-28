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
    create_pages_blueprint,
    create_schedules_blueprint,
    create_settings_blueprint,
    create_tags_blueprint,
    create_webhooks_blueprint,
)
from app.services.container_service import ContainerService
from app.services.docker_hosts import DockerHostManager
from app.services.docker_service import DockerService
from app.services.notification_service import NotificationService
from app.services.update_service import UpdateService
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
docker_service = DockerService(docker_manager)
notification_service = NotificationService(settings_repo)
container_service = ContainerService(
    docker_service=docker_service,
    logs_repo=logs_repo,
    schedule_repo=schedule_repo,
    notification_service=notification_service,
    container_tag_repo=container_tag_repo,
    webui_url_repo=webui_url_repo,
)
update_service = UpdateService(
    update_status_repo=update_status_repo,
    docker_manager=docker_manager,
    scheduler=scheduler,
    get_setting=get_setting,
    validate_cron_expression=validate_cron_expression,
    logger=logger,
    cache_ttl_seconds=UPDATE_STATUS_CACHE_TTL_SECONDS,
    update_check_cron_default=UPDATE_CHECK_CRON_DEFAULT,
)

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
    user_repo=user_repo,
    limiter=limiter,
    csrf=csrf,
    version=VERSION,
    logger=logger,
    bcrypt_module=bcrypt,
)
app.register_blueprint(auth_blueprint)

logs_blueprint = create_logs_blueprint(app_log_repo=app_log_repo, version=VERSION)
app.register_blueprint(logs_blueprint)

settings_blueprint = create_settings_blueprint(
    get_setting=get_setting,
    set_setting=set_setting,
    configure_update_check_schedule=update_service.configure_update_check_schedule,
    notification_service=notification_service,
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
    container_service=container_service,
    sanitize_string=sanitize_string,
    logger=logger,
)
app.register_blueprint(webhooks_blueprint)

images_blueprint = create_images_blueprint(
    api_key_or_login_required=api_key_or_login_required,
    clear_image_usage_cache=clear_image_usage_cache,
    fetch_all_images=fetch_all_images,
    docker_manager=docker_manager,
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
    container_service=container_service,
    update_service=update_service,
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
    container_service=container_service,
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

pages_blueprint = create_pages_blueprint(version=VERSION)
app.register_blueprint(pages_blueprint)






def load_schedules():
    """Load all enabled schedules from database and add to scheduler"""
    schedules = schedule_repo.list_enabled()

    for schedule in schedules:
        schedule_id, host_id, container_id, container_name, action, cron_expr, one_time, run_at = schedule
        try:
            action_map = {
                'restart': container_service.restart_container,
                'start': container_service.start_container,
                'stop': container_service.stop_container,
                'pause': container_service.pause_container,
                'unpause': container_service.unpause_container,
                'update': container_service.update_container,
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
    update_status_map = update_service.load_update_status_map()

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
    update_service.configure_update_check_schedule()
    
    # Run Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
