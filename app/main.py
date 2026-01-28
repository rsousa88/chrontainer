"""
Chrontainer - Docker Container Scheduler
Main Flask application
"""
import os
import time
import sqlite3
import bcrypt
import secrets
import hashlib
import hmac
import threading
from flask import Flask, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
import logging
from functools import wraps
from dotenv import load_dotenv
import re
from typing import Tuple, Optional

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
from app.services.container_query_service import ContainerQueryService
from app.services.container_service import ContainerService
from app.services.disk_usage_service import DiskUsageService
from app.services.host_metrics_service import HostMetricsService
from app.services.docker_hosts import DockerHostManager
from app.services.docker_service import DockerService
from app.services.image_service import ImageService
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

HOST_METRICS_CACHE_TTL_SECONDS = 20
CONTAINER_STATS_CACHE_TTL_SECONDS = 10
DISK_USAGE_CACHE_TTL_SECONDS = 300
IMAGE_USAGE_CACHE_TTL_SECONDS = 180
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

# Background scheduler for cron/one-time jobs
scheduler = BackgroundScheduler()
scheduler.start()

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
host_metrics_service = HostMetricsService(
    host_metrics_repo=host_metrics_repo,
    docker_manager=docker_manager,
    cache_ttl_seconds=HOST_METRICS_CACHE_TTL_SECONDS,
)
disk_usage_service = DiskUsageService(
    logger=logger,
    cache_ttl_seconds=DISK_USAGE_CACHE_TTL_SECONDS,
)
container_query_service = ContainerQueryService(
    docker_manager=docker_manager,
    host_repo=host_repo,
    container_tag_repo=container_tag_repo,
    webui_url_repo=webui_url_repo,
    update_service=update_service,
    host_default_color=HOST_DEFAULT_COLOR,
    get_contrast_text_color=get_contrast_text_color,
    strip_image_tag=strip_image_tag,
    get_image_links=get_image_links,
    cache_ttl_seconds=CONTAINER_STATS_CACHE_TTL_SECONDS,
)
image_service = ImageService(
    docker_manager=docker_manager,
    host_repo=host_repo,
    logger=logger,
    host_default_color=HOST_DEFAULT_COLOR,
    get_contrast_text_color=get_contrast_text_color,
    split_image_reference=split_image_reference,
    extract_repository_from_digest=extract_repository_from_digest,
    get_cached_disk_usage=disk_usage_service.get_cached_disk_usage,
    refresh_disk_usage_async=disk_usage_service.refresh_disk_usage_async,
    cache_ttl_seconds=IMAGE_USAGE_CACHE_TTL_SECONDS,
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
    clear_image_usage_cache=image_service.clear_image_usage_cache,
    fetch_all_images=image_service.fetch_all_images,
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
    host_metrics_service=host_metrics_service,
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
    fetch_all_containers=container_query_service.fetch_all_containers,
    get_cached_container_stats=container_query_service.get_cached_container_stats,
    set_cached_container_stats=container_query_service.set_cached_container_stats,
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
