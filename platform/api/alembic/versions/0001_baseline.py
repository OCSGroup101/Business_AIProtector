"""Baseline schema — public.tenants + RLS scaffolding.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-03-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─── Public schema tables ─────────────────────────────────────────────────

    op.create_table(
        "tenants",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("keycloak_realm", sa.String(128), nullable=False),
        sa.Column("minio_bucket", sa.String(128), nullable=False),
        sa.Column("schema_name", sa.String(128), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("plan", sa.String(32), nullable=False, server_default="standard"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        schema="public",
    )

    # ─── Enable app.tenant_id parameter for RLS ───────────────────────────────
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_settings WHERE name = 'app.tenant_id'
            ) THEN
                -- Set a default so the parameter is always defined
                PERFORM set_config('app.tenant_id', '', false);
            END IF;
        END $$;
    """)

    # ─── Per-tenant schema creation function ─────────────────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION create_tenant_schema(p_tenant_id TEXT)
        RETURNS void AS $$
        DECLARE
            schema_name TEXT := 'tenant_' || replace(p_tenant_id, '-', '_');
        BEGIN
            EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', schema_name);

            -- agents
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I.agents (
                    id              VARCHAR(30) PRIMARY KEY,
                    tenant_id       VARCHAR(30) NOT NULL,
                    hostname        VARCHAR(256) NOT NULL,
                    os_platform     VARCHAR(32) NOT NULL,
                    os_version      VARCHAR(64) NOT NULL,
                    os_arch         VARCHAR(16) NOT NULL,
                    agent_version   VARCHAR(32) NOT NULL,
                    state           VARCHAR(16) NOT NULL DEFAULT ''ENROLLING'',
                    policy_id       VARCHAR(30),
                    policy_version  INTEGER NOT NULL DEFAULT 0,
                    cert_serial     VARCHAR(64),
                    cert_expires_at TIMESTAMPTZ,
                    last_heartbeat_at TIMESTAMPTZ,
                    last_heartbeat_metrics JSONB,
                    is_active       BOOLEAN NOT NULL DEFAULT true,
                    enrolled_at     TIMESTAMPTZ,
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at      TIMESTAMPTZ,
                    tags            JSONB DEFAULT ''{}''::jsonb
                )', schema_name);

            -- incidents
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I.incidents (
                    id                  VARCHAR(30) PRIMARY KEY,
                    tenant_id           VARCHAR(30) NOT NULL,
                    agent_id            VARCHAR(30) NOT NULL,
                    hostname            VARCHAR(256) NOT NULL,
                    rule_id             VARCHAR(64) NOT NULL,
                    rule_name           VARCHAR(256) NOT NULL,
                    severity            VARCHAR(16) NOT NULL,
                    mitre_techniques    JSONB,
                    status              VARCHAR(24) NOT NULL DEFAULT ''OPEN'',
                    assigned_to         VARCHAR(256),
                    summary             TEXT,
                    containment_status  VARCHAR(24),
                    containment_actions JSONB,
                    first_seen_at       TIMESTAMPTZ NOT NULL,
                    last_seen_at        TIMESTAMPTZ NOT NULL,
                    resolved_at         TIMESTAMPTZ,
                    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
                )', schema_name);

            -- incident_events
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I.incident_events (
                    id          SERIAL PRIMARY KEY,
                    incident_id VARCHAR(30) NOT NULL REFERENCES %I.incidents(id) ON DELETE CASCADE,
                    event_id    VARCHAR(30) NOT NULL UNIQUE,
                    event_type  VARCHAR(64) NOT NULL,
                    event_json  JSONB NOT NULL,
                    occurred_at TIMESTAMPTZ NOT NULL
                )', schema_name, schema_name);

            -- policies
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I.policies (
                    id            VARCHAR(30) PRIMARY KEY,
                    tenant_id     VARCHAR(30) NOT NULL,
                    name          VARCHAR(256) NOT NULL,
                    description   TEXT,
                    version       INTEGER NOT NULL DEFAULT 1,
                    content_toml  TEXT NOT NULL,
                    signature     TEXT,
                    is_default    BOOLEAN NOT NULL DEFAULT false,
                    is_active     BOOLEAN NOT NULL DEFAULT true,
                    agent_count   INTEGER NOT NULL DEFAULT 0,
                    created_by    VARCHAR(256),
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at    TIMESTAMPTZ
                )', schema_name);

            -- audit_logs
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I.audit_logs (
                    id            VARCHAR(30) PRIMARY KEY,
                    tenant_id     VARCHAR(30) NOT NULL,
                    actor_id      VARCHAR(256) NOT NULL,
                    actor_role    VARCHAR(64) NOT NULL,
                    actor_ip      VARCHAR(64),
                    action        VARCHAR(128) NOT NULL,
                    resource_type VARCHAR(64) NOT NULL,
                    resource_id   VARCHAR(256),
                    details       JSONB,
                    outcome       VARCHAR(16) NOT NULL DEFAULT ''SUCCESS'',
                    failure_reason TEXT,
                    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now()
                )', schema_name);

            -- ioc_entries
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %I.ioc_entries (
                    id              VARCHAR(30) PRIMARY KEY,
                    tenant_id       VARCHAR(30) NOT NULL,
                    ioc_type        VARCHAR(32) NOT NULL,
                    value           VARCHAR(512) NOT NULL,
                    value_lower     VARCHAR(512) NOT NULL,
                    confidence      FLOAT NOT NULL DEFAULT 0.7,
                    sources         JSONB,
                    tags            JSONB,
                    mitre_techniques JSONB,
                    first_seen      TIMESTAMPTZ NOT NULL,
                    last_seen       TIMESTAMPTZ NOT NULL,
                    expires_at      TIMESTAMPTZ,
                    is_active       BOOLEAN NOT NULL DEFAULT true,
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                )', schema_name);

            -- RLS policies
            EXECUTE format('ALTER TABLE %I.agents ENABLE ROW LEVEL SECURITY', schema_name);
            EXECUTE format('ALTER TABLE %I.incidents ENABLE ROW LEVEL SECURITY', schema_name);
            EXECUTE format('ALTER TABLE %I.policies ENABLE ROW LEVEL SECURITY', schema_name);
            EXECUTE format('ALTER TABLE %I.audit_logs ENABLE ROW LEVEL SECURITY', schema_name);
            EXECUTE format('ALTER TABLE %I.ioc_entries ENABLE ROW LEVEL SECURITY', schema_name);

            -- RLS: tenant_id must match current_setting('app.tenant_id')
            FOR t IN SELECT unnest(ARRAY[''agents'',''incidents'',''policies'',''audit_logs'',''ioc_entries'']) LOOP
                EXECUTE format(
                    'CREATE POLICY tenant_isolation ON %I.%I
                     USING (tenant_id = current_setting(''app.tenant_id'', true))',
                    schema_name, t
                );
            END LOOP;

        END;
        $$ LANGUAGE plpgsql;
    """)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS create_tenant_schema(TEXT)")
    op.drop_table("tenants", schema="public")
