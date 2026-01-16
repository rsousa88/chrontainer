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
                    container_list.append({
                        'id': container.id[:12],
                        'name': container.name,
                        'status': container.status,
                        'image': container.image.tags[0] if container.image.tags else 'unknown',
                        'created': container.attrs['Created'],
                        'host_id': host_id,
                        'host_name': host_name
                    })
            except Exception as e:
                logger.error(f"Error getting containers from host {host_name}: {e}")

        # Get schedules with host info
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.id, s.container_name, s.action, s.cron_expression, s.enabled, s.last_run, h.name
            FROM schedules s
            LEFT JOIN hosts h ON s.host_id = h.id
        ''')
        schedules = cursor.fetchall()
        conn.close()

        return render_template('index.html', containers=container_list, schedules=schedules)
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
                    container_list.append({
                        'id': container.id[:12],
                        'name': container.name,
                        'status': container.status,
                        'image': container.image.tags[0] if container.image.tags else 'unknown',
                        'host_id': host_id,
                        'host_name': host_name
                    })
            except Exception as e:
                logger.error(f"Error getting containers from host {host_name}: {e}")
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

@app.route('/api/container/<container_id>/logs', methods=['GET'])
def api_get_container_logs(container_id):
    """API endpoint to get container logs"""
    host_id = request.args.get('host_id', 1, type=int)
    tail = request.args.get('tail', 100, type=int)  # Default to last 100 lines
    timestamps = request.args.get('timestamps', 'true').lower() == 'true'

    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            return jsonify({'error': f'Cannot connect to Docker host {host_id}'}), 500

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
    except Exception as e:
        logger.error(f"Failed to get logs for container {container_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/schedule', methods=['POST'])
def add_schedule():
    """Add a new schedule"""
    data = request.json
    container_id = data.get('container_id')
    container_name = data.get('container_name')
    action = data.get('action', 'restart')
    cron_expression = data.get('cron_expression')
    host_id = data.get('host_id', 1)

    if not all([container_id, container_name, cron_expression]):
        return jsonify({'error': 'Missing required fields'}), 400

    # Validate cron expression
    try:
        parts = cron_expression.split()
        if len(parts) != 5:
            return jsonify({'error': 'Invalid cron expression. Must be: minute hour day month day_of_week'}), 400

        trigger = CronTrigger(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4]
        )
    except Exception as e:
        return jsonify({'error': f'Invalid cron expression: {str(e)}'}), 400

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
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get all settings"""
    try:
        webhook_url = get_setting('discord_webhook_url', '')
        return jsonify({
            'discord_webhook_url': webhook_url
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/discord', methods=['POST'])
def update_discord_settings():
    """Update Discord webhook settings"""
    try:
        data = request.json
        webhook_url = data.get('webhook_url', '').strip()

        if webhook_url and not webhook_url.startswith('https://discord.com/api/webhooks/'):
            return jsonify({'error': 'Invalid Discord webhook URL'}), 400

        set_setting('discord_webhook_url', webhook_url)
        logger.info(f"Discord webhook URL updated")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to update Discord settings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings/discord/test', methods=['POST'])
def test_discord_webhook():
    """Test Discord webhook"""
    try:
        webhook_url = get_setting('discord_webhook_url')
        if not webhook_url:
            return jsonify({'error': 'No Discord webhook URL configured'}), 400

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
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts', methods=['POST'])
def add_host():
    """Add a new Docker host"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        url = data.get('url', '').strip()

        if not name or not url:
            return jsonify({'error': 'Name and URL are required'}), 400

        # Test connection first
        success, message = docker_manager.test_connection(url)
        if not success:
            return jsonify({'error': f'Connection test failed: {message}'}), 400

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
    except Exception as e:
        logger.error(f"Failed to add host: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<int:host_id>', methods=['PUT'])
def update_host(host_id):
    """Update a Docker host"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        url = data.get('url', '').strip()
        enabled = data.get('enabled', True)

        if not name or not url:
            return jsonify({'error': 'Name and URL are required'}), 400

        # Don't allow disabling the local host
        if host_id == 1 and not enabled:
            return jsonify({'error': 'Cannot disable the local host'}), 400

        # Test connection if URL changed
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT url FROM hosts WHERE id = ?', (host_id,))
        current_url = cursor.fetchone()[0]
        conn.close()

        if url != current_url:
            success, message = docker_manager.test_connection(url)
            if not success:
                return jsonify({'error': f'Connection test failed: {message}'}), 400

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
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<int:host_id>', methods=['DELETE'])
def delete_host(host_id):
    """Delete a Docker host"""
    try:
        # Don't allow deleting the local host
        if host_id == 1:
            return jsonify({'error': 'Cannot delete the local host'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # Check if host has any schedules
        cursor.execute('SELECT COUNT(*) FROM schedules WHERE host_id = ?', (host_id,))
        count = cursor.fetchone()[0]
        if count > 0:
            conn.close()
            return jsonify({'error': f'Cannot delete host with {count} active schedules'}), 400

        cursor.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
        conn.commit()
        conn.close()

        # Clear cached client
        docker_manager.clear_cache(host_id)

        logger.info(f"Deleted host {host_id}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete host: {e}")
        return jsonify({'error': str(e)}), 500

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

@app.route('/settings')
def settings_page():
    """Settings page"""
    webhook_url = get_setting('discord_webhook_url', '')
    return render_template('settings.html', discord_webhook_url=webhook_url)

@app.route('/hosts')
def hosts_page():
    """Hosts management page"""
    return render_template('hosts.html')

@app.route('/logs')
def logs():
    """View logs page"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100')
    logs = cursor.fetchall()
    conn.close()
    return render_template('logs.html', logs=logs)

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
