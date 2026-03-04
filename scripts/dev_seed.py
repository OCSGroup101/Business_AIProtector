#!/usr/bin/env python3
# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Dev seed script — bootstraps the OpenClaw dev database.

Connects directly to PostgreSQL (bypasses the API) and:
  1. Creates the public schema tables (via Alembic — run separately with `make db-migrate`)
  2. Provisions the 'dev' tenant schema (agents, incidents, policies, audit_logs, ioc_entries + RLS)
  3. Creates a one-time enrollment token and prints it for use with --enroll

Usage:
    python scripts/dev_seed.py

Environment variables (all have dev defaults):
    DATABASE_URL           postgresql+asyncpg://openclaw:openclaw_dev_password@localhost:5432/openclaw
    OPENCLAW_DEV_TENANT_ID dev
    OPENCLAW_ADMIN_TOKEN   dev-admin-token
"""

import asyncio
import hashlib
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

import asyncpg

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://openclaw:openclaw_dev_password@localhost:5432/openclaw",
)
# asyncpg uses a plain dsn without the +asyncpg dialect prefix
PG_DSN = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

TENANT_ID = os.getenv("OPENCLAW_DEV_TENANT_ID", "dev")
TENANT_NAME = "Development Tenant"
TENANT_SLUG = "dev"


def _print(msg: str) -> None:
    print(msg, flush=True)


async def seed() -> None:
    _print(f"Connecting to {PG_DSN.split('@')[1] if '@' in PG_DSN else PG_DSN}")

    conn = await asyncpg.connect(PG_DSN)
    try:
        # ── 1. Upsert tenant row ──────────────────────────────────────────────
        schema_name = f"tenant_{TENANT_ID.replace('-', '_')}"

        existing = await conn.fetchval(
            "SELECT id FROM public.tenants WHERE id = $1", TENANT_ID
        )
        if existing:
            _print(f"Tenant '{TENANT_ID}' already exists — skipping insert")
        else:
            await conn.execute(
                """
                INSERT INTO public.tenants
                    (id, name, slug, keycloak_realm, minio_bucket, schema_name,
                     is_active, plan, created_at)
                VALUES ($1, $2, $3, 'openclaw-platform', $4, $5, true, 'standard', now())
                """,
                TENANT_ID,
                TENANT_NAME,
                TENANT_SLUG,
                f"openclaw-{TENANT_SLUG}",
                schema_name,
            )
            _print(f"Tenant '{TENANT_ID}' created")

        # ── 2. Provision tenant schema ────────────────────────────────────────
        await conn.execute("SELECT create_tenant_schema($1)", TENANT_ID)
        _print(f"Schema '{schema_name}' provisioned (or already exists)")

        # ── 3. Create dev enrollment token ────────────────────────────────────
        plaintext = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        token_id = f"tok_dev_{TENANT_ID}"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=720)  # 30 days

        # Delete any existing dev token for idempotency
        await conn.execute(
            "DELETE FROM public.enrollment_tokens WHERE id = $1", token_id
        )
        await conn.execute(
            """
            INSERT INTO public.enrollment_tokens
                (id, tenant_id, token_hash, label, created_by,
                 created_at, expires_at, max_uses, use_count, is_active)
            VALUES ($1, $2, $3, 'dev-seed', 'dev_seed.py',
                    now(), $4, 10, 0, true)
            """,
            token_id,
            TENANT_ID,
            token_hash,
            expires_at,
        )
        _print(f"Enrollment token created (id={token_id}, max_uses=10, expires={expires_at.date()})")

    finally:
        await conn.close()

    # ── Print instructions ────────────────────────────────────────────────────
    _print("")
    _print("=" * 60)
    _print("Dev seed complete. To enroll an agent:")
    _print("")
    _print(f"  export OPENCLAW_ENROLL_TOKEN='{plaintext}'")
    _print("")
    _print("  # From the agent directory:")
    _print("  cargo run -- --enroll $OPENCLAW_ENROLL_TOKEN --config ../openclaw-agent.dev.toml")
    _print("  cargo run -- --config ../openclaw-agent.dev.toml")
    _print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(seed())
    except Exception as exc:
        _print(f"ERROR: {exc}")
        sys.exit(1)
