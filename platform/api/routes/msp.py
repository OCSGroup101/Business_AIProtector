# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
MSP (Managed Security Provider) endpoints — cross-tenant operator API.

All routes require the MSP_OPERATOR role via get_msp_actor() dependency.
MSP operators bypass tenant scoping and can query all tenants' data.

Endpoints:
  GET  /api/v1/msp/tenants                              List all tenants with stats
  GET  /api/v1/msp/summary                              Aggregate platform-wide counts
  GET  /api/v1/msp/tenants/{tenant_id}/summary          Per-tenant header stats
  POST /api/v1/msp/tenants                              Provision a new tenant
  POST /api/v1/msp/tenants/{tenant_id}/enrollment-token Generate an enrollment token
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from ..database import get_db
from ..middleware.rbac import get_msp_actor
from ..models.enrollment_token import EnrollmentToken
from ..models.tenant import Tenant

logger = logging.getLogger(__name__)

router = APIRouter()


def _safe(value: object) -> str:
    """Strip newlines before logging to prevent log injection."""
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


# ─── Pydantic models ──────────────────────────────────────────────────────────


class TenantWithStats(BaseModel):
    id: str
    name: str
    slug: str
    schema_name: str
    plan: str
    is_active: bool
    created_at: datetime
    agent_count: int
    open_incident_count: int


class PlatformSummary(BaseModel):
    total_tenants: int
    active_tenants: int
    total_agents: int
    total_incidents: int
    critical_incidents: int


class TenantSummary(BaseModel):
    tenant_id: str
    name: str
    agent_count: int
    open_incident_count: int
    critical_incident_count: int


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


class CreateEnrollmentTokenRequest(BaseModel):
    label: Optional[str] = Field(None, description="Human-readable label for audit")
    max_uses: int = Field(1, ge=1, le=100)
    expires_hours: int = Field(24, ge=1, le=720)


class EnrollmentTokenResponse(BaseModel):
    id: str
    tenant_id: str
    label: Optional[str]
    token: str = Field(..., description="Plaintext token — shown once, store securely")
    max_uses: int
    expires_at: datetime


# ─── Helper: fetch per-tenant agent/incident counts ───────────────────────────


async def _tenant_stats(db: AsyncSession, schema: str) -> tuple[int, int]:
    """
    Return (agent_count, open_incident_count) for the given tenant schema.
    Returns (0, 0) if the schema or tables do not yet exist.
    """
    try:
        agent_row = await db.execute(
            text(f"SELECT COUNT(*) FROM {schema}.agents")  # nosec B608
        )
        agent_count: int = agent_row.scalar_one() or 0

        incident_row = await db.execute(
            text(
                f"SELECT COUNT(*) FROM {schema}.incidents "  # nosec B608
                f"WHERE status NOT IN ('resolved', 'closed')"
            )
        )
        incident_count: int = incident_row.scalar_one() or 0

        return agent_count, incident_count
    except Exception:
        # Schema or tables may not exist yet for a freshly provisioned tenant.
        return 0, 0


# ─── Routes ───────────────────────────────────────────────────────────────────


@router.get(
    "/tenants",
    response_model=list[TenantWithStats],
    summary="List all tenants with agent and incident counts",
)
async def list_tenants(
    actor: dict = Depends(get_msp_actor),
    db: AsyncSession = Depends(get_db),
) -> list[TenantWithStats]:
    """Return all provisioned tenants enriched with live agent and incident counts."""
    result = await db.execute(select(Tenant).order_by(Tenant.created_at))
    tenants = result.scalars().all()

    out: list[TenantWithStats] = []
    for t in tenants:
        agent_count, incident_count = await _tenant_stats(db, t.schema_name)
        out.append(
            TenantWithStats(
                id=t.id,
                name=t.name,
                slug=t.slug,
                schema_name=t.schema_name,
                plan=t.plan,
                is_active=t.is_active,
                created_at=t.created_at,
                agent_count=agent_count,
                open_incident_count=incident_count,
            )
        )
    return out


@router.get(
    "/summary",
    response_model=PlatformSummary,
    summary="Aggregate platform-wide counts",
)
async def platform_summary(
    actor: dict = Depends(get_msp_actor),
    db: AsyncSession = Depends(get_db),
) -> PlatformSummary:
    """Return aggregate counts across all tenants."""
    result = await db.execute(select(Tenant))
    tenants = result.scalars().all()

    total_agents = 0
    total_incidents = 0
    critical_incidents = 0
    active_tenants = 0

    for t in tenants:
        if t.is_active:
            active_tenants += 1
        schema = t.schema_name
        try:
            a_row = await db.execute(text(f"SELECT COUNT(*) FROM {schema}.agents"))  # nosec B608
            total_agents += a_row.scalar_one() or 0

            i_row = await db.execute(
                text(
                    f"SELECT COUNT(*) FROM {schema}.incidents "  # nosec B608
                    f"WHERE status NOT IN ('resolved', 'closed')"
                )
            )
            total_incidents += i_row.scalar_one() or 0

            c_row = await db.execute(
                text(
                    f"SELECT COUNT(*) FROM {schema}.incidents "  # nosec B608
                    f"WHERE severity = 'critical' AND status NOT IN ('resolved', 'closed')"
                )
            )
            critical_incidents += c_row.scalar_one() or 0
        except Exception:
            pass

    return PlatformSummary(
        total_tenants=len(tenants),
        active_tenants=active_tenants,
        total_agents=total_agents,
        total_incidents=total_incidents,
        critical_incidents=critical_incidents,
    )


@router.get(
    "/tenants/{tenant_id}/summary",
    response_model=TenantSummary,
    summary="Per-tenant header stats",
)
async def tenant_summary(
    tenant_id: str,
    actor: dict = Depends(get_msp_actor),
    db: AsyncSession = Depends(get_db),
) -> TenantSummary:
    """Return agent and incident counts for a single tenant."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    schema = tenant.schema_name
    agent_count, open_count = await _tenant_stats(db, schema)

    critical_count = 0
    try:
        c_row = await db.execute(
            text(
                f"SELECT COUNT(*) FROM {schema}.incidents "  # nosec B608
                f"WHERE severity = 'critical' AND status NOT IN ('resolved', 'closed')"
            )
        )
        critical_count = c_row.scalar_one() or 0
    except Exception:
        pass

    return TenantSummary(
        tenant_id=tenant.id,
        name=tenant.name,
        agent_count=agent_count,
        open_incident_count=open_count,
        critical_incident_count=critical_count,
    )


@router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision a new tenant",
)
async def create_tenant(
    body: CreateTenantRequest,
    actor: dict = Depends(get_msp_actor),
    db: AsyncSession = Depends(get_db),
) -> TenantResponse:
    """
    Create a tenant record and provision its PostgreSQL schema.

    Idempotent — returns the existing tenant if already present.
    Calls the create_tenant_schema() PG function installed by migration 0001.
    """
    schema_name = f"tenant_{body.id.replace('-', '_')}"
    now = datetime.now(timezone.utc)

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
        await db.flush()

    await db.execute(text("SELECT create_tenant_schema(:tid)"), {"tid": body.id})
    await db.commit()

    logger.info(
        "MSP provisioned tenant: id=%s schema=%s actor=%s",
        _safe(body.id),
        _safe(schema_name),
        _safe(actor.get("actor_id", "unknown")),
    )

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        schema_name=schema_name,
        plan=tenant.plan,
        created_at=tenant.created_at,
    )


@router.post(
    "/tenants/{tenant_id}/enrollment-token",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an enrollment token for a tenant",
)
async def create_enrollment_token(
    tenant_id: str,
    body: CreateEnrollmentTokenRequest,
    actor: dict = Depends(get_msp_actor),
    db: AsyncSession = Depends(get_db),
) -> EnrollmentTokenResponse:
    """
    Create a one-time enrollment token for agents to use during --enroll.

    The plaintext token is returned exactly once. Only its SHA-256 hash is stored.
    """
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    plaintext = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=body.expires_hours)
    token_id = f"tok_{ULID()}"

    record = EnrollmentToken(
        id=token_id,
        tenant_id=tenant_id,
        token_hash=token_hash,
        label=body.label,
        created_by="msp",
        created_at=now,
        expires_at=expires_at,
        max_uses=body.max_uses,
        use_count=0,
        is_active=True,
    )
    db.add(record)
    await db.commit()

    logger.info(
        "MSP created enrollment token: id=%s tenant=%s label=%s expires=%s actor=%s",
        _safe(token_id),
        _safe(tenant_id),
        _safe(body.label),
        expires_at.isoformat(),
        _safe(actor.get("actor_id", "unknown")),
    )

    return EnrollmentTokenResponse(
        id=token_id,
        tenant_id=tenant_id,
        label=body.label,
        token=plaintext,
        max_uses=body.max_uses,
        expires_at=expires_at,
    )
