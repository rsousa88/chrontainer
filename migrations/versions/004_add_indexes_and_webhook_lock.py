"""Add indexes for performance and webhook lock column

Revision ID: 004
Revises: 003
Create Date: 2026-01-20
"""
from alembic import op
import sqlalchemy as sa

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add index on api_keys.key_hash for faster lookups
    op.create_index('idx_api_keys_key_hash', 'api_keys', ['key_hash'])

    # Add index on webhooks.token for faster lookups
    op.create_index('idx_webhooks_token', 'webhooks', ['token'])

    # Add locked column to webhooks table
    op.add_column('webhooks', sa.Column('locked', sa.Integer, default=0))


def downgrade() -> None:
    op.drop_column('webhooks', 'locked')
    op.drop_index('idx_webhooks_token', 'webhooks')
    op.drop_index('idx_api_keys_key_hash', 'api_keys')
