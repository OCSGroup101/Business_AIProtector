# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add reports table for generated PDF/HTML report tracking.

Revision ID: 0009_reports
Revises: 0008_deployments
Create Date: 2026-03-08
"""

from alembic import op
import sqlalchemy as sa

revision = "0009_reports"
down_revision = "0008_deployments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("storage_key", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_reports_tenant_id", "reports", ["tenant_id"])
    op.create_index("ix_reports_status", "reports", ["status"])


def downgrade() -> None:
    op.drop_index("ix_reports_status", table_name="reports")
    op.drop_index("ix_reports_tenant_id", table_name="reports")
    op.drop_table("reports")
