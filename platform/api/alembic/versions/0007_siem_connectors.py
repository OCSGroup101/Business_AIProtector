# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add siem_connectors table for SIEM integration registrations.

Revision ID: 0007_siem_connectors
Revises: 0006_community_ioc
Create Date: 2026-03-08
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_siem_connectors"
down_revision = "0006_community_ioc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "siem_connectors",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("connector_type", sa.String(32), nullable=False),
        sa.Column("config_encrypted", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_test_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_test_ok", sa.Boolean, nullable=True),
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
    op.create_index("ix_siem_connectors_tenant_id", "siem_connectors", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_siem_connectors_tenant_id", table_name="siem_connectors")
    op.drop_table("siem_connectors")
