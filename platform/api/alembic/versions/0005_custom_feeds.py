# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add custom_feeds table for TAXII/STIX feed registrations.

Revision ID: 0005_custom_feeds
Revises: 0004_policy_rule_overrides
Create Date: 2026-03-08
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_custom_feeds"
down_revision = "0004_policy_rule_overrides"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custom_feeds",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("taxii_url", sa.String(2048), nullable=False),
        sa.Column("collection_id", sa.String(256), nullable=False),
        sa.Column("api_key_encrypted", sa.Text, nullable=True),
        sa.Column("last_cursor", sa.String(64), nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, default=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_custom_feeds_tenant_id", "custom_feeds", ["tenant_id"])


def downgrade() -> None:
    op.drop_table("custom_feeds")
