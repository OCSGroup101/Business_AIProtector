# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Community IOC sharing pipeline.

POST /api/v1/intel/community/submit  — tenant submits a new IOC
GET  /api/v1/intel/community/feed    — returns a STIX bundle (tenant_id stripped)

Rate limit: Redis sliding window — max 10 submissions per tenant per hour.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ulid import ULID

from ..database import get_tenant_session
from ..models.community_ioc import CommunityIoc
from ..middleware.rbac import Permission, require_permission, Role
from ..audit_service import emit as audit_emit

logger = logging.getLogger(__name__)

router = APIRouter()

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
RATE_LIMIT_PER_HOUR = 10


async def _get_redis() -> aioredis.Redis:
    return await aioredis.from_url(REDIS_URL, decode_responses=True)


class CommunityIocSubmit(BaseModel):
    ioc_type: str
    value: str
    score: float = 0.5


class CommunityIocResponse(BaseModel):
    id: str
    ioc_type: str
    value: str
    score: float
    verification_status: str
    created_at: datetime


@router.post("/submit", response_model=CommunityIocResponse, status_code=status.HTTP_201_CREATED)
async def submit_community_ioc(
    body: CommunityIocSubmit = Body(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INTEL_WRITE)),
) -> CommunityIocResponse:
    """Submit a new community IOC.  Rate-limited to 10/hour per tenant."""
    tenant_id = (
        getattr(http_request.state, "tenant_id", None) if http_request else None
    ) or "dev_tenant"

    # ── Rate limiting via Redis sliding window ────────────────────────────
    try:
        r = await _get_redis()
        hour_bucket = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H")
        rate_key = f"community_submit:{tenant_id}:{hour_bucket}"
        current = await r.incr(rate_key)
        if current == 1:
            await r.expire(rate_key, 3600)
        if current > RATE_LIMIT_PER_HOUR:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: max {RATE_LIMIT_PER_HOUR} submissions/hour",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Rate limit check failed (Redis unavailable): %s", exc)

    ioc = CommunityIoc(
        id=f"cioc_{ULID()}",
        tenant_id=tenant_id,
        submitted_by=role.value,
        ioc_type=body.ioc_type,
        value=body.value,
        score=body.score,
        verification_status="pending",
        created_at=datetime.now(tz=timezone.utc),
    )
    db.add(ioc)
    await db.flush()

    actor_ip = http_request.client.host if http_request and http_request.client else None
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="community_ioc.submitted",
        resource_type="community_ioc",
        resource_id=ioc.id,
        outcome="SUCCESS",
        details={"ioc_type": ioc.ioc_type, "value": ioc.value[:64]},
        tenant_id=tenant_id,
    )

    return CommunityIocResponse(
        id=ioc.id,
        ioc_type=ioc.ioc_type,
        value=ioc.value,
        score=ioc.score,
        verification_status=ioc.verification_status,
        created_at=ioc.created_at,
    )


@router.get("/feed")
async def get_community_feed(
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INTEL_READ)),
) -> dict:
    """
    Return a STIX 2.1 bundle of community IOCs.
    tenant_id is stripped from all entries before export.
    """
    result = await db.execute(
        select(CommunityIoc).where(
            CommunityIoc.verification_status.in_(["verified", "pending"])
        )
    )
    iocs = result.scalars().all()

    indicators = []
    for ioc in iocs:
        pattern = _to_stix_pattern(ioc.ioc_type, ioc.value)
        if not pattern:
            continue
        indicators.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.id}",
                "created": ioc.created_at.isoformat(),
                "modified": ioc.created_at.isoformat(),
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc.created_at.isoformat(),
                "confidence": int(ioc.score * 100),
                "labels": [ioc.ioc_type, ioc.verification_status],
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{ULID()}",
        "spec_version": "2.1",
        "objects": indicators,
    }


def _to_stix_pattern(ioc_type: str, value: str) -> Optional[str]:
    """Convert an IOC to a STIX pattern string."""
    mapping = {
        "file_hash": f"[file:hashes.'SHA-256' = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "ip": f"[ipv4-addr:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "email": f"[email-addr:value = '{value}']",
    }
    return mapping.get(ioc_type)
