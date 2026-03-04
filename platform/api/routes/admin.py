# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

"""
Admin endpoints — protected by static OPENCLAW_ADMIN_TOKEN header.
Not behind Keycloak RBAC; intended for operator bootstrap operations only.

Endpoints:
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
from sqlalchemy import select
from ulid import ULID

from ..database import get_db
from ..models.enrollment_token import EnrollmentToken

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


# ─── Request / Response models ────────────────────────────────────────────────


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
