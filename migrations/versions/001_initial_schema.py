"""Initial schema baseline

Revision ID: 001
Revises:
Create Date: 2026-01-19

This migration documents the initial database schema for Chrontainer v0.2.0.
It creates all the tables needed for the application to function.

For existing databases, this migration should be marked as complete using:
    alembic stamp 001
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the initial database schema"""

    # Create hosts table
    op.create_table(
        'hosts',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('name', sa.Text, nullable=False, unique=True),
        sa.Column('url', sa.Text, nullable=False),
        sa.Column('enabled', sa.Integer, default=1),
        sa.Column('color', sa.Text, default='#e8f4f8'),
        sa.Column('last_seen', sa.DateTime),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp())
    )

    # Create schedules table
    op.create_table(
        'schedules',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('host_id', sa.Integer, sa.ForeignKey('hosts.id'), nullable=False, default=1),
        sa.Column('container_id', sa.Text, nullable=False),
        sa.Column('container_name', sa.Text, nullable=False),
        sa.Column('action', sa.Text, nullable=False),
        sa.Column('cron_expression', sa.Text, nullable=False),
        sa.Column('enabled', sa.Integer, default=1),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp()),
        sa.Column('last_run', sa.DateTime),
        sa.Column('next_run', sa.DateTime)
    )

    # Create logs table
    op.create_table(
        'logs',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('schedule_id', sa.Integer),
        sa.Column('host_id', sa.Integer, sa.ForeignKey('hosts.id'), default=1),
        sa.Column('container_name', sa.Text),
        sa.Column('action', sa.Text),
        sa.Column('status', sa.Text),
        sa.Column('message', sa.Text),
        sa.Column('timestamp', sa.DateTime, server_default=sa.func.current_timestamp())
    )

    # Create settings table
    op.create_table(
        'settings',
        sa.Column('key', sa.Text, primary_key=True),
        sa.Column('value', sa.Text),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.current_timestamp())
    )

    # Create tags table
    op.create_table(
        'tags',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('name', sa.Text, nullable=False, unique=True),
        sa.Column('color', sa.Text, default='#3498db'),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp())
    )

    # Create container_tags table (many-to-many relationship)
    op.create_table(
        'container_tags',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('container_id', sa.Text, nullable=False),
        sa.Column('host_id', sa.Integer, sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('tag_id', sa.Integer, sa.ForeignKey('tags.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint('container_id', 'host_id', 'tag_id')
    )

    # Create container_webui_urls table
    op.create_table(
        'container_webui_urls',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('container_id', sa.Text, nullable=False),
        sa.Column('host_id', sa.Integer, sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('url', sa.Text, nullable=False),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint('container_id', 'host_id')
    )

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('username', sa.Text, nullable=False, unique=True),
        sa.Column('password_hash', sa.Text, nullable=False),
        sa.Column('role', sa.Text, nullable=False, default='viewer'),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp()),
        sa.Column('last_login', sa.DateTime)
    )


def downgrade() -> None:
    """Drop all tables"""
    op.drop_table('users')
    op.drop_table('container_webui_urls')
    op.drop_table('container_tags')
    op.drop_table('tags')
    op.drop_table('settings')
    op.drop_table('logs')
    op.drop_table('schedules')
    op.drop_table('hosts')
