# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

"""
Admin endpoints — protected by static OPENCLAW_ADMIN_TOKEN header.
Not behind Keycloak RBAC; intended for operator bootstrap operations only.

Endpoints:
  POST /api/v1/admin/tenants              Provision a new tenant schema
  GET  /api/v1/admin/tenants              List tenants

  POST /api/v1/admin/enrollment-tokens   Create a one-time agent enrollment token
  GET  /api/v1/admin/enrollment-tokens   List tokens for a tenant (without plaintext)
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from ulid import ULID

from ..database import get_db
from ..models.enrollment_token import EnrollmentToken
from ..models.tenant import Tenant

logger = logging.getLogger(__name__)

router = APIRouter()

_ADMIN_TOKEN_ENV = "OPENCLAW_ADMIN_TOKEN"
_DEV_FALLBACK_TOKEN = "dev-admin-token"  # only used when OPENCLAW_DEV_MODE=true


# ─── Auth ─────────────────────────────────────────────────────────────────────


def _require_admin(request: Request) -> None:
    """Verify the X-Admin-Token header against OPENCLAW_ADMIN_TOKEN env var."""
    dev_mode = os.getenv("OPENCLAW_DEV_MODE", "").lower() == "true"
    expected = os.getenv(_ADMIN_TOKEN_ENV, _DEV_FALLBACK_TOKEN if dev_mode else "")

    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{_ADMIN_TOKEN_ENV} environment variable is not set",
        )

    provided = request.headers.get("X-Admin-Token", "")
    if not secrets.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin token",
        )


# ─── Tenant models ────────────────────────────────────────────────────────────


class CreateTenantRequest(BaseModel):
    id: str = Field(
        ...,
        pattern=r"^[a-zA-Z0-9_]{1,50}$",
        description="Tenant ID — alphanumeric + underscores, used as schema suffix",
    )
    name: str = Field(..., max_length=256)
    slug: str = Field(..., pattern=r"^[a-z0-9-]{1,64}$")
    plan: str = Field("standard", description="standard | enterprise")


class TenantResponse(BaseModel):
    id: str
    name: str
    slug: str
    schema_name: str
    plan: str
    created_at: datetime


# ─── Tenant endpoints ─────────────────────────────────────────────────────────


@router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision a new tenant",
)
async def create_tenant(
    body: CreateTenantRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TenantResponse:
    """
    Create a tenant record and provision its PostgreSQL schema with all tables and RLS policies.

    This calls the create_tenant_schema() PG function defined in migration 0001_baseline.
    Safe to call multiple times — uses CREATE SCHEMA IF NOT EXISTS and CREATE TABLE IF NOT EXISTS.
    """
    _require_admin(request)

    schema_name = f"tenant_{body.id.replace('-', '_')}"
    now = datetime.now(timezone.utc)

    # Idempotency: return existing tenant if already present
    existing = await db.execute(select(Tenant).where(Tenant.id == body.id))
    tenant = existing.scalar_one_or_none()

    if tenant is None:
        tenant = Tenant(
            id=body.id,
            name=body.name,
            slug=body.slug,
            keycloak_realm="openclaw-platform",
            minio_bucket=f"openclaw-{body.slug}",
            schema_name=schema_name,
            is_active=True,
            plan=body.plan,
            created_at=now,
        )
        db.add(tenant)
        await db.flush()  # persist before schema creation

    # Provision (or re-provision) the PG schema via the migration-installed function
    await db.execute(text("SELECT create_tenant_schema(:tid)"), {"tid": body.id})
    await db.commit()

    logger.info("Tenant provisioned: id=%s schema=%s", body.id, schema_name)

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        schema_name=schema_name,
        plan=tenant.plan,
        created_at=tenant.created_at,
    )


@router.get(
    "/tenants",
    response_model=list[TenantResponse],
    summary="List tenants",
)
async def list_tenants(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> list[TenantResponse]:
    """List all provisioned tenants."""
    _require_admin(request)

    result = await db.execute(select(Tenant).order_by(Tenant.created_at))
    rows = result.scalars().all()
    return [
        TenantResponse(
            id=t.id,
            name=t.name,
            slug=t.slug,
            schema_name=t.schema_name,
            plan=t.plan,
            created_at=t.created_at,
        )
        for t in rows
    ]


# ─── Enrollment token models ──────────────────────────────────────────────────


class CreateTokenRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant this token grants enrollment into")
    label: Optional[str] = Field(None, description="Human-readable label for audit purposes")
    max_uses: int = Field(1, ge=1, le=100, description="Maximum enrollment uses (default: 1)")
    expires_hours: int = Field(
        24, ge=1, le=720, description="Hours until token expires (default: 24, max: 720)"
    )


class TokenCreatedResponse(BaseModel):
    id: str
    tenant_id: str
    label: Optional[str]
    token: str = Field(..., description="Plaintext token — shown once, store securely")
    max_uses: int
    expires_at: datetime


class TokenSummary(BaseModel):
    id: str
    tenant_id: str
    label: Optional[str]
    max_uses: int
    use_count: int
    is_active: bool
    expires_at: datetime
    created_at: datetime


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post(
    "/enrollment-tokens",
    response_model=TokenCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an enrollment token",
)
async def create_enrollment_token(
    body: CreateTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenCreatedResponse:
    """
    Create a one-time enrollment token for an agent to use during --enroll.

    The plaintext token is returned once and never stored. Deliver it to the
    endpoint out-of-band (e.g. via secrets manager or SSH). Only the SHA-256
    hash is persisted for validation.
    """
    _require_admin(request)

    plaintext = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=body.expires_hours)
    token_id = f"tok_{ULID()}"

    record = EnrollmentToken(
        id=token_id,
        tenant_id=body.tenant_id,
        token_hash=token_hash,
        label=body.label,
        created_by="admin",
        created_at=now,
        expires_at=expires_at,
        max_uses=body.max_uses,
        use_count=0,
        is_active=True,
    )
    db.add(record)
    await db.commit()

    logger.info(
        "Enrollment token created: id=%s tenant=%s label=%r expires=%s",
        token_id,
        body.tenant_id,
        body.label,
        expires_at.isoformat(),
    )

    return TokenCreatedResponse(
        id=token_id,
        tenant_id=body.tenant_id,
        label=body.label,
        token=plaintext,
        max_uses=body.max_uses,
        expires_at=expires_at,
    )


@router.get(
    "/enrollment-tokens",
    response_model=list[TokenSummary],
    summary="List enrollment tokens for a tenant",
)
async def list_enrollment_tokens(
    tenant_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> list[TokenSummary]:
    """List all enrollment tokens for a tenant (plaintext never returned)."""
    _require_admin(request)

    result = await db.execute(
        select(EnrollmentToken)
        .where(EnrollmentToken.tenant_id == tenant_id)
        .order_by(EnrollmentToken.created_at.desc())
    )
    rows = result.scalars().all()

    return [
        TokenSummary(
            id=r.id,
            tenant_id=r.tenant_id,
            label=r.label,
            max_uses=r.max_uses,
            use_count=r.use_count,
            is_active=r.is_active,
            expires_at=r.expires_at,
            created_at=r.created_at,
        )
        for r in rows
    ]
