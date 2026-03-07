# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Add rule_overrides JSON column to per-tenant policies table.

rule_overrides stores per-rule enabled/disabled overrides as a JSON object:
  { "<rule_id>": { "enabled": false } }

Rules absent from this map inherit the enabled flag from the policy TOML.

Revision ID: 0004_policy_rule_overrides
Revises: 0003_global_ioc_entries
Create Date: 2026-03-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_policy_rule_overrides"
down_revision = "0003_global_ioc_entries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Applied inside each tenant schema by the migration runner.
    # Default is an empty JSON object (no overrides — all rules follow TOML).
    op.add_column(
        "policies",
        sa.Column(
            "rule_overrides",
            sa.JSON(),
            nullable=False,
            server_default="{}",
        ),
    )


def downgrade() -> None:
    op.drop_column("policies", "rule_overrides")
