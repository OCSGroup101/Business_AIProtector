# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add public.global_ioc_entries table for threat intelligence IOC feed data.

Revision ID: 0003_global_ioc_entries
Revises: 0002_enrollment_tokens
Create Date: 2026-03-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_global_ioc_entries"
down_revision = "0002_enrollment_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "global_ioc_entries",
        sa.Column("id", sa.String(30), primary_key=True, nullable=False),
        sa.Column("ioc_type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("value_lower", sa.String(512), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("feed_metadata", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="public",
    )
    op.create_index(
        "ix_global_ioc_value_lower",
        "global_ioc_entries",
        ["value_lower"],
        schema="public",
    )
    op.create_unique_constraint(
        "uq_global_ioc_type_value",
        "global_ioc_entries",
        ["ioc_type", "value_lower"],
        schema="public",
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_global_ioc_type_value", "global_ioc_entries", schema="public"
    )
    op.drop_index("ix_global_ioc_value_lower", "global_ioc_entries", schema="public")
    op.drop_table("global_ioc_entries", schema="public")
