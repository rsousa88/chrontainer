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

# Initialize Docker client
try:
    docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')
    logger.info("Docker client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Docker client: {e}")
    docker_client = None

# Initialize APScheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Database initialization
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('/data/chrontainer.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            container_id TEXT NOT NULL,
            container_name TEXT NOT NULL,
            action TEXT NOT NULL,
            cron_expression TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_run TIMESTAMP,
            next_run TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id INTEGER,
            container_name TEXT,
            action TEXT,
            status TEXT,
            message TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    logger.info("Database initialized")

def get_db():
    """Get database connection"""
    return sqlite3.connect('/data/chrontainer.db')

def restart_container(container_id, container_name, schedule_id=None):
    """Restart a Docker container"""
    try:
        container = docker_client.containers.get(container_id)
        container.restart()
        message = f"Container {container_name} restarted successfully"
        logger.info(message)
        log_action(schedule_id, container_name, 'restart', 'success', message)
        
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
        log_action(schedule_id, container_name, 'restart', 'error', message)
        return False, message

def start_container(container_id, container_name):
    """Start a Docker container"""
    try:
        container = docker_client.containers.get(container_id)
        container.start()
        message = f"Container {container_name} started successfully"
        logger.info(message)
        log_action(None, container_name, 'start', 'success', message)
        return True, message
    except Exception as e:
        message = f"Failed to start container {container_name}: {str(e)}"
        logger.error(message)
        log_action(None, container_name, 'start', 'error', message)
        return False, message

def stop_container(container_id, container_name):
    """Stop a Docker container"""
    try:
        container = docker_client.containers.get(container_id)
        container.stop()
        message = f"Container {container_name} stopped successfully"
        logger.info(message)
        log_action(None, container_name, 'stop', 'success', message)
        return True, message
    except Exception as e:
        message = f"Failed to stop container {container_name}: {str(e)}"
        logger.error(message)
        log_action(None, container_name, 'stop', 'error', message)
        return False, message

def log_action(schedule_id, container_name, action, status, message):
    """Log an action to the database"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO logs (schedule_id, container_name, action, status, message) VALUES (?, ?, ?, ?, ?)',
            (schedule_id, container_name, action, status, message)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log action: {e}")

def load_schedules():
    """Load all enabled schedules from database and add to scheduler"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, container_id, container_name, action, cron_expression FROM schedules WHERE enabled = 1')
    schedules = cursor.fetchall()
    conn.close()
    
    for schedule in schedules:
        schedule_id, container_id, container_name, action, cron_expr = schedule
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
            
            if action == 'restart':
                scheduler.add_job(
                    restart_container,
                    trigger,
                    args=[container_id, container_name, schedule_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True
                )
                logger.info(f"Loaded schedule {schedule_id}: {container_name} - {cron_expr}")
        except Exception as e:
            logger.error(f"Failed to load schedule {schedule_id}: {e}")

# Routes
@app.route('/')
def index():
    """Main dashboard"""
    if not docker_client:
        return render_template('error.html', error="Docker client not available")
    
    try:
        containers = docker_client.containers.list(all=True)
        container_list = []
        for container in containers:
            container_list.append({
                'id': container.id[:12],
                'name': container.name,
                'status': container.status,
                'image': container.image.tags[0] if container.image.tags else 'unknown',
                'created': container.attrs['Created']
            })
        
        # Get schedules
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, container_name, action, cron_expression, enabled, last_run FROM schedules')
        schedules = cursor.fetchall()
        conn.close()
        
        return render_template('index.html', containers=container_list, schedules=schedules)
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/containers')
def get_containers():
    """API endpoint to get all containers"""
    if not docker_client:
        return jsonify({'error': 'Docker client not available'}), 500
    
    try:
        containers = docker_client.containers.list(all=True)
        container_list = []
        for container in containers:
            container_list.append({
                'id': container.id[:12],
                'name': container.name,
                'status': container.status,
                'image': container.image.tags[0] if container.image.tags else 'unknown'
            })
        return jsonify(container_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/container/<container_id>/restart', methods=['POST'])
def api_restart_container(container_id):
    """API endpoint to restart a container"""
    container_name = request.json.get('name', 'unknown')
    success, message = restart_container(container_id, container_name)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/start', methods=['POST'])
def api_start_container(container_id):
    """API endpoint to start a container"""
    container_name = request.json.get('name', 'unknown')
    success, message = start_container(container_id, container_name)
    return jsonify({'success': success, 'message': message})

@app.route('/api/container/<container_id>/stop', methods=['POST'])
def api_stop_container(container_id):
    """API endpoint to stop a container"""
    container_name = request.json.get('name', 'unknown')
    success, message = stop_container(container_id, container_name)
    return jsonify({'success': success, 'message': message})

@app.route('/api/schedule', methods=['POST'])
def add_schedule():
    """Add a new schedule"""
    data = request.json
    container_id = data.get('container_id')
    container_name = data.get('container_name')
    action = data.get('action', 'restart')
    cron_expression = data.get('cron_expression')
    
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
            'INSERT INTO schedules (container_id, container_name, action, cron_expression) VALUES (?, ?, ?, ?)',
            (container_id, container_name, action, cron_expression)
        )
        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Add to scheduler
        scheduler.add_job(
            restart_container,
            trigger,
            args=[container_id, container_name, schedule_id],
            id=f"schedule_{schedule_id}",
            replace_existing=True
        )
        
        logger.info(f"Added schedule {schedule_id}: {container_name} - {cron_expression}")
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
        cursor.execute('SELECT enabled, container_id, container_name, cron_expression FROM schedules WHERE id = ?', (schedule_id,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'error': 'Schedule not found'}), 404
        
        enabled, container_id, container_name, cron_expression = result
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
                args=[container_id, container_name, schedule_id],
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
