# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Threat hunting query interface — natural language → structured incident query."""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_tenant_session
from ..hunting.query_engine import HuntingQuery, translate_hunting_query
from ..middleware.rbac import Permission, Role, require_permission
from ..models.incident import Incident

logger = logging.getLogger(__name__)

router = APIRouter()


class HuntingRequest(BaseModel):
    query: str  # natural language query


class HuntingQueryResponse(BaseModel):
    query: HuntingQuery
    results: list[dict[str, Any]]
    result_count: int
    execution_time_ms: float


@router.post(
    "/",
    response_model=HuntingQueryResponse,
    status_code=status.HTTP_200_OK,
)
async def hunt(
    body: HuntingRequest = Body(...),
    request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INCIDENTS_READ)),
) -> HuntingQueryResponse:
    """
    Translate a natural-language threat hunting query and execute it against
    the incident store.

    Example queries:
    - "Show me all CRITICAL incidents in the last 24 hours"
    - "Find PowerShell execution incidents this week on any host"
    - "List unresolved persistence incidents involving T1547"
    - "Show lateral movement detections from the last 3 days"
    """
    t0 = time.monotonic()

    structured = await translate_hunting_query(body.query)

    since = datetime.now(tz=timezone.utc) - timedelta(hours=structured.time_range_hours)
    q = select(Incident).where(Incident.first_seen_at >= since)

    # Apply filters from structured query
    filters = structured.filters or {}

    if structured.event_type:
        # Map event_type to rule_name keyword search (best effort)
        q = q.where(Incident.rule_name.ilike(f"%{structured.event_type}%"))

    if "severity" in filters:
        q = q.where(Incident.severity == str(filters["severity"]).upper())

    if "hostname" in filters:
        q = q.where(Incident.hostname.ilike(f"%{filters['hostname']}%"))

    if "rule_id" in filters:
        q = q.where(Incident.rule_id == filters["rule_id"])

    if "status" in filters:
        q = q.where(Incident.status == str(filters["status"]).upper())

    if "agent_id" in filters:
        q = q.where(Incident.agent_id == filters["agent_id"])

    q = q.order_by(Incident.first_seen_at.desc()).limit(structured.limit)

    result = await db.execute(q)
    incidents = result.scalars().all()

    rows = [
        {
            "id": inc.id,
            "hostname": inc.hostname,
            "agent_id": inc.agent_id,
            "rule_id": inc.rule_id,
            "rule_name": inc.rule_name,
            "severity": inc.severity,
            "status": inc.status,
            "mitre_techniques": inc.mitre_techniques or [],
            "first_seen_at": inc.first_seen_at.isoformat(),
            "last_seen_at": inc.last_seen_at.isoformat(),
        }
        for inc in incidents
    ]

    elapsed_ms = (time.monotonic() - t0) * 1000

    return HuntingQueryResponse(
        query=structured,
        results=rows,
        result_count=len(rows),
        execution_time_ms=round(elapsed_ms, 2),
    )
