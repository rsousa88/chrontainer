"""
Chrontainer - Docker Container Scheduler
Main Flask application
"""
import os
import docker
import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
import logging

# Version
VERSION = "0.2.0"

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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

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
            conn = sqlite3.connect('/data/chrontainer.db')
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
            conn = sqlite3.connect('/data/chrontainer.db')
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
            conn = sqlite3.connect('/data/chrontainer.db')
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

            if not remote_digest or not local_digest:
                return False, None, "Unable to compare digests"

            # Compare digests
            has_update = (remote_digest != local_digest)
            return has_update, remote_digest, None

        except docker.errors.APIError as e:
            # Handle rate limits, authentication errors, etc.
            return False, None, f"Registry error: {str(e)}"

    except Exception as e:
        logger.error(f"Error checking for update: {e}")
        return False, None, str(e)

def update_container(container_id, container_name, host_id):
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

        logger.info(f"Successfully updated container {container_name}")
        return True, f"Container updated successfully"

    except Exception as e:
        logger.error(f"Failed to update container {container_name}: {e}")
        return False, f"Update failed: {str(e)}"

# Initialize APScheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Database initialization
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('/data/chrontainer.db')
    cursor = conn.cursor()

    # Create hosts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            url TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
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

    # Insert default local host if not exists
    cursor.execute('''
        INSERT OR IGNORE INTO hosts (id, name, url, enabled, last_seen)
        VALUES (1, 'Local', 'unix://var/run/docker.sock', 1, ?)
    ''', (datetime.now(),))

    # Migration: Add host_id column to existing schedules if needed
    cursor.execute("PRAGMA table_info(schedules)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'host_id' not in columns:
        logger.info("Migrating schedules table - adding host_id column")
        cursor.execute('ALTER TABLE schedules ADD COLUMN host_id INTEGER NOT NULL DEFAULT 1')

    # Migration: Add host_id column to existing logs if needed
    cursor.execute("PRAGMA table_info(logs)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'host_id' not in columns:
        logger.info("Migrating logs table - adding host_id column")
        cursor.execute('ALTER TABLE logs ADD COLUMN host_id INTEGER DEFAULT 1')

    conn.commit()
    conn.close()
    logger.info("Database initialized")

def get_db():
    """Get database connection"""
    return sqlite3.connect('/data/chrontainer.db')

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

def load_schedules():
    """Load all enabled schedules from database and add to scheduler"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, host_id, container_id, container_name, action, cron_expression FROM schedules WHERE enabled = 1')
    schedules = cursor.fetchall()
    conn.close()

    for schedule in schedules:
        schedule_id, host_id, container_id, container_name, action, cron_expr = schedule
        try:
            # Parse cron expression (minute hour day month day_of_week)
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

            # Select the appropriate action function
            if action == 'restart':
                action_func = restart_container
            elif action == 'start':
                action_func = start_container
            elif action == 'stop':
                action_func = stop_container
            elif action == 'pause':
                action_func = pause_container
            elif action == 'unpause':
                action_func = unpause_container
            else:
                logger.error(f"Unknown action '{action}' for schedule {schedule_id}")
                continue

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
def index():
    """Main dashboard"""
    try:
        container_list = []

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

                    container_list.append({
                        'id': container.id[:12],
                        'name': container.name,
                        'status': container.status,
                        'image': image_name,
                        'created': container.attrs['Created'],
                        'host_id': host_id,
                        'host_name': host_name,
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
            SELECT s.id, s.container_name, s.action, s.cron_expression, s.enabled, s.last_run, h.name
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
def get_containers():
    """API endpoint to get all containers"""
    try:
        container_list = []
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

                    container_list.append({
                        'id': container.id[:12],
                        'name': container.name,
                        'status': container.status,
                        'image': image_name,
                        'host_id': host_id,
                        'host_name': host_name,
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
def api_restart_container(container_id):
    """API endpoint to restart a container"""
    data = request.json
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = restart_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/start', methods=['POST'])
def api_start_container(container_id):
    """API endpoint to start a container"""
    data = request.json
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = start_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/stop', methods=['POST'])
def api_stop_container(container_id):
    """API endpoint to stop a container"""
    data = request.json
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = stop_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/pause', methods=['POST'])
def api_pause_container(container_id):
    """API endpoint to pause a container"""
    data = request.json
    container_name = data.get('name', 'unknown')
    host_id = data.get('host_id', 1)
    success, message = pause_container(container_id, container_name, host_id=host_id)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/unpause', methods=['POST'])
def api_unpause_container(container_id):
    """API endpoint to unpause a container"""
    data = request.json
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
        has_update, remote_digest, error = check_for_update(container, client)

        if error:
            return jsonify({'has_update': False, 'error': error})

        return jsonify({'has_update': has_update, 'remote_digest': remote_digest})

    except docker.errors.NotFound:
        return jsonify({'error': 'Container not found'}), 404
    except Exception as e:
        logger.error(f"Error checking for update: {e}")
        return jsonify({'error': 'Failed to check for updates'}), 500

@app.route('/api/container/<container_id>/update', methods=['POST'])
def api_update_container(container_id):
    """API endpoint to update a container"""
    data = request.json
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

@app.route('/api/schedule', methods=['POST'])
def add_schedule():
    """Add a new schedule"""
    data = request.json
    container_id = data.get('container_id')
    container_name = data.get('container_name')
    action = data.get('action', 'restart')
    cron_expression = data.get('cron_expression')
    host_id = data.get('host_id', 1)

    if not container_id:
        return jsonify({'error': 'Container ID is required'}), 400
    if not container_name:
        return jsonify({'error': 'Container name is required'}), 400
    if not cron_expression:
        return jsonify({'error': 'Cron expression is required'}), 400

    # Validate cron expression
    try:
        parts = cron_expression.split()
        if len(parts) != 5:
            return jsonify({'error': 'Invalid cron expression format. Must be 5 fields: minute hour day month day_of_week (example: "0 2 * * *" for 2 AM daily)'}), 400

        trigger = CronTrigger(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4]
        )
    except ValueError as e:
        return jsonify({'error': f'Invalid cron expression values. Please check your cron syntax. Common patterns: "0 2 * * *" (2 AM daily), "*/15 * * * *" (every 15 min)'}), 400
    except Exception as e:
        return jsonify({'error': 'Failed to parse cron expression. Please verify your syntax using a tool like crontab.guru'}), 400

    # Save to database
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO schedules (host_id, container_id, container_name, action, cron_expression) VALUES (?, ?, ?, ?, ?)',
            (host_id, container_id, container_name, action, cron_expression)
        )
        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Add to scheduler with the appropriate action function
        if action == 'restart':
            action_func = restart_container
        elif action == 'start':
            action_func = start_container
        elif action == 'stop':
            action_func = stop_container
        elif action == 'pause':
            action_func = pause_container
        elif action == 'unpause':
            action_func = unpause_container
        else:
            return jsonify({'error': f'Invalid action: {action}'}), 400

        scheduler.add_job(
            action_func,
            trigger,
            args=[container_id, container_name, schedule_id, host_id],
            id=f"schedule_{schedule_id}",
            replace_existing=True
        )

        logger.info(f"Added schedule {schedule_id}: {container_name} - {action} - {cron_expression}")
        return jsonify({'success': True, 'schedule_id': schedule_id})
    except Exception as e:
        logger.error(f"Failed to add schedule: {e}")
        return jsonify({'error': 'Failed to create schedule. Please check the logs for details.'}), 500

@app.route('/api/schedule/<int:schedule_id>', methods=['DELETE'])
def delete_schedule(schedule_id):
    """Delete a schedule"""
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
def toggle_schedule(schedule_id):
    """Enable/disable a schedule"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT enabled, host_id, container_id, container_name, cron_expression FROM schedules WHERE id = ?', (schedule_id,))
        result = cursor.fetchone()

        if not result:
            return jsonify({'error': 'Schedule not found'}), 404

        enabled, host_id, container_id, container_name, cron_expression = result
        new_enabled = 0 if enabled else 1

        cursor.execute('UPDATE schedules SET enabled = ? WHERE id = ?', (new_enabled, schedule_id))
        conn.commit()
        conn.close()

        # Update scheduler
        if new_enabled:
            parts = cron_expression.split()
            trigger = CronTrigger(
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4]
            )
            scheduler.add_job(
                restart_container,
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
            'discord_webhook_url': webhook_url
        })
    except Exception as e:
        logger.error(f"Failed to get settings: {e}")
        return jsonify({'error': 'Failed to load settings. Please check the database connection.'}), 500

@app.route('/api/settings/discord', methods=['POST'])
def update_discord_settings():
    """Update Discord webhook settings"""
    try:
        data = request.json
        webhook_url = data.get('webhook_url', '').strip()

        if webhook_url and not webhook_url.startswith('https://discord.com/api/webhooks/'):
            return jsonify({'error': 'Invalid Discord webhook URL. It should start with "https://discord.com/api/webhooks/". You can create one in Discord Server Settings > Integrations > Webhooks.'}), 400

        set_setting('discord_webhook_url', webhook_url)
        logger.info(f"Discord webhook URL updated")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to update Discord settings: {e}")
        return jsonify({'error': 'Failed to save Discord webhook settings. Please try again.'}), 500

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

@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    """Get all Docker hosts"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, url, enabled, last_seen, created_at FROM hosts ORDER BY id')
        hosts = cursor.fetchall()
        conn.close()

        host_list = []
        for host in hosts:
            host_list.append({
                'id': host[0],
                'name': host[1],
                'url': host[2],
                'enabled': bool(host[3]),
                'last_seen': host[4],
                'created_at': host[5]
            })
        return jsonify(host_list)
    except Exception as e:
        logger.error(f"Failed to get hosts: {e}")
        return jsonify({'error': 'Failed to load Docker hosts. Please check the database connection.'}), 500

@app.route('/api/hosts', methods=['POST'])
def add_host():
    """Add a new Docker host"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        url = data.get('url', '').strip()

        if not name:
            return jsonify({'error': 'Host name is required'}), 400
        if not url:
            return jsonify({'error': 'Host URL is required (e.g., tcp://192.168.1.100:2375 or unix:///var/run/docker.sock)'}), 400

        # Test connection first
        success, message = docker_manager.test_connection(url)
        if not success:
            return jsonify({'error': f'Connection test failed: {message}. Please ensure the Docker host is running and accessible, and that you have set up a socket-proxy for remote hosts.'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO hosts (name, url, enabled, last_seen) VALUES (?, ?, 1, ?)',
            (name, url, datetime.now())
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
def update_host(host_id):
    """Update a Docker host"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        url = data.get('url', '').strip()
        enabled = data.get('enabled', True)

        if not name:
            return jsonify({'error': 'Host name is required'}), 400
        if not url:
            return jsonify({'error': 'Host URL is required'}), 400

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
            'UPDATE hosts SET name = ?, url = ?, enabled = ? WHERE id = ?',
            (name, url, 1 if enabled else 0, host_id)
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
def settings_page():
    """Settings page"""
    webhook_url = get_setting('discord_webhook_url', '')
    return render_template('settings.html', discord_webhook_url=webhook_url, version=VERSION)

@app.route('/hosts')
def hosts_page():
    """Hosts management page"""
    return render_template('hosts.html', version=VERSION)

@app.route('/logs')
def logs():
    """View logs page"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
    logs = cursor.fetchall()
    conn.close()
    return render_template('logs.html', logs=logs, version=VERSION)

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
