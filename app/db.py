from __future__ import annotations

import logging
import os
import re
import sqlite3
from datetime import datetime

import bcrypt

from app.config import Config

logger = logging.getLogger(__name__)

DATABASE_PATH = Config.DATABASE_PATH
HOST_DEFAULT_COLOR = '#e8f4f8'


def _get_database_path() -> str:
    """Resolve database path at runtime (supports tests overriding env)."""
    return os.getenv('DATABASE_PATH', DATABASE_PATH)


def get_db() -> sqlite3.Connection:
    """Get database connection."""
    return sqlite3.connect(_get_database_path())


def init_db() -> None:
    """Initialize SQLite database."""
    conn = sqlite3.connect(_get_database_path())
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

    # Cache for update checks
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS update_status (
            container_id TEXT NOT NULL,
            host_id INTEGER NOT NULL,
            has_update INTEGER DEFAULT 0,
            remote_digest TEXT,
            error TEXT,
            note TEXT,
            checked_at TIMESTAMP,
            PRIMARY KEY (container_id, host_id)
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
            locked INTEGER DEFAULT 0,
            last_triggered TIMESTAMP,
            trigger_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add locked column if it doesn't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE webhooks ADD COLUMN locked INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass

    # Create default admin user if no users exist
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]
    if user_count == 0:
        default_password = 'admin'
        password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        ''', ('admin', password_hash.decode('utf-8'), 'admin'))
        logger.info("Created default admin user (username: admin, password: admin) - PLEASE CHANGE THE PASSWORD!")

    # Migration: Add host_id column to existing schedules if needed
    cursor.execute('PRAGMA table_info(schedules)')
    columns = [col[1] for col in cursor.fetchall()]
    if 'host_id' not in columns:
        logger.info('Migrating schedules table - adding host_id column')
        cursor.execute('ALTER TABLE schedules ADD COLUMN host_id INTEGER NOT NULL DEFAULT 1')
    if 'one_time' not in columns:
        logger.info('Migrating schedules table - adding one_time column')
        cursor.execute('ALTER TABLE schedules ADD COLUMN one_time INTEGER DEFAULT 0')
    if 'run_at' not in columns:
        logger.info('Migrating schedules table - adding run_at column')
        cursor.execute('ALTER TABLE schedules ADD COLUMN run_at TIMESTAMP')

    # Migration: Add host_id column to existing logs if needed
    cursor.execute('PRAGMA table_info(logs)')
    columns = [col[1] for col in cursor.fetchall()]
    if 'host_id' not in columns:
        logger.info('Migrating logs table - adding host_id column')
        cursor.execute('ALTER TABLE logs ADD COLUMN host_id INTEGER DEFAULT 1')

    # Migration: Add color column to hosts if needed
    cursor.execute('PRAGMA table_info(hosts)')
    columns = [col[1] for col in cursor.fetchall()]
    if 'color' not in columns:
        logger.info('Migrating hosts table - adding color column')
        if not re.match(r'^#[0-9a-fA-F]{6}$', HOST_DEFAULT_COLOR):
            raise ValueError(f'Invalid HOST_DEFAULT_COLOR constant: {HOST_DEFAULT_COLOR}')
        cursor.execute(f"ALTER TABLE hosts ADD COLUMN color TEXT DEFAULT '{HOST_DEFAULT_COLOR}'")
        cursor.execute('UPDATE hosts SET color = ? WHERE color IS NULL OR color = ""', (HOST_DEFAULT_COLOR,))

    # Insert default local host if not exists
    cursor.execute('''
        INSERT OR IGNORE INTO hosts (id, name, url, enabled, color, last_seen)
        VALUES (1, 'Local', 'unix://var/run/docker.sock', 1, ?, ?)
    ''', (HOST_DEFAULT_COLOR, datetime.now()))

    # Create indexes for performance optimization
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON schedules(enabled)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_schedules_host_id ON schedules(host_id)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_schedule_id ON logs(schedule_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_host_id ON logs(host_id)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_container_tags_container ON container_tags(container_id, host_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_container_tags_tag_id ON container_tags(tag_id)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_webhooks_token ON webhooks(token)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_webui_urls_container ON container_webui_urls(container_id, host_id)')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_update_status_checked_at ON update_status(checked_at)')

    conn.commit()
    conn.close()
    logger.info('Database initialized')


def ensure_data_dir() -> None:
    data_dir = os.path.dirname(DATABASE_PATH) or '.'
    os.makedirs(data_dir, exist_ok=True)
