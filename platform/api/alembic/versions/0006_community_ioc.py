# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add community_iocs table for cross-tenant IOC sharing.

Revision ID: 0006_community_ioc
Revises: 0005_custom_feeds
Create Date: 2026-03-08
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_community_ioc"
down_revision = "0005_custom_feeds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "community_iocs",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False, index=True),
        sa.Column("submitted_by", sa.String(256), nullable=False),
        sa.Column("ioc_type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("score", sa.Float, nullable=False, default=0.5),
        sa.Column(
            "verification_status", sa.String(16), nullable=False, default="pending"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_community_iocs_tenant_id", "community_iocs", ["tenant_id"])
    op.create_index(
        "ix_community_iocs_verification_status",
        "community_iocs",
        ["verification_status"],
    )


def downgrade() -> None:
    op.drop_table("community_iocs")
