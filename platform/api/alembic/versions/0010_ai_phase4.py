# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add Phase 4 AI columns: analyst FP feedback fields on incidents table.

Revision ID: 0010_ai_phase4
Revises: 0009_reports
Create Date: 2026-03-08
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_ai_phase4"
down_revision = "0009_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add false-positive feedback columns to incidents
    op.add_column(
        "incidents",
        sa.Column("is_false_positive", sa.Boolean(), nullable=True, server_default=sa.false()),
    )
    op.add_column(
        "incidents",
        sa.Column("fp_notes", sa.Text(), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "analyst_reviewed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Index for efficient FP-rate queries per rule
    op.create_index(
        "ix_incidents_rule_reviewed",
        "incidents",
        ["rule_id", "analyst_reviewed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_incidents_rule_reviewed", table_name="incidents")
    op.drop_column("incidents", "analyst_reviewed_at")
    op.drop_column("incidents", "fp_notes")
    op.drop_column("incidents", "is_false_positive")
