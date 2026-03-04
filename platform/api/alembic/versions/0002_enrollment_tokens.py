"""Add public.enrollment_tokens table.

Revision ID: 0002_enrollment_tokens
Revises: 0001_baseline
Create Date: 2026-03-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_enrollment_tokens"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("tenant_id", sa.String(30), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(256), nullable=True),
        sa.Column("created_by", sa.String(256), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by_agent_id", sa.String(30), nullable=True),
        sa.Column("max_uses", sa.Integer, nullable=False, server_default="1"),
        sa.Column("use_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        schema="public",
    )
    op.create_index(
        "ix_enrollment_tokens_tenant_id",
        "enrollment_tokens",
        ["tenant_id"],
        schema="public",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_enrollment_tokens_tenant_id",
        table_name="enrollment_tokens",
        schema="public",
    )
    op.drop_table("enrollment_tokens", schema="public")
