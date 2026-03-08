# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add deployments table for staged agent update rollouts.

Revision ID: 0008_deployments
Revises: 0007_siem_connectors
Create Date: 2026-03-08
"""

from alembic import op
import sqlalchemy as sa

revision = "0008_deployments"
down_revision = "0007_siem_connectors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "deployments",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False, server_default="stable"),
        sa.Column("rollout_pct", sa.Integer, nullable=False, server_default="0"),
        sa.Column("target_os", sa.String(16), nullable=True),
        sa.Column("binary_url", sa.String(2048), nullable=False),
        sa.Column("binary_sha256", sa.String(64), nullable=False),
        sa.Column("signature_url", sa.String(2048), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column(
            "auto_rollback_threshold",
            sa.Float,
            nullable=False,
            server_default="0.05",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_deployments_channel", "deployments", ["channel"])
    op.create_index("ix_deployments_status", "deployments", ["status"])


def downgrade() -> None:
    op.drop_index("ix_deployments_status", table_name="deployments")
    op.drop_index("ix_deployments_channel", table_name="deployments")
    op.drop_table("deployments")
