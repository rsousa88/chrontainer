"""Add API keys and webhooks tables

Revision ID: 003
Revises: 002
Create Date: 2026-01-19
"""
from alembic import op
import sqlalchemy as sa

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.Text, nullable=False),
        sa.Column('key_hash', sa.Text, nullable=False),
        sa.Column('key_prefix', sa.Text, nullable=False),
        sa.Column('permissions', sa.Text, default='read'),
        sa.Column('last_used', sa.DateTime, nullable=True),
        sa.Column('expires_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp())
    )

    op.create_table(
        'webhooks',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('name', sa.Text, nullable=False),
        sa.Column('token', sa.Text, nullable=False, unique=True),
        sa.Column('container_id', sa.Text, nullable=True),
        sa.Column('host_id', sa.Integer, nullable=True),
        sa.Column('action', sa.Text, nullable=False),
        sa.Column('enabled', sa.Integer, default=1),
        sa.Column('last_triggered', sa.DateTime, nullable=True),
        sa.Column('trigger_count', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp())
    )


def downgrade() -> None:
    op.drop_table('webhooks')
    op.drop_table('api_keys')
