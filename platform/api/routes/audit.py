"""Audit log endpoint — read-only, append-only."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from ..database import get_db
from ..models.audit_log import AuditLog
from ..middleware.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()


class AuditEntry(BaseModel):
    id: str
    actor_id: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    outcome: str
    occurred_at: datetime


class AuditListResponse(BaseModel):
    entries: list[AuditEntry]
    total: int


@router.get("", response_model=AuditListResponse)
async def list_audit_logs(
    actor_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    limit: int = Query(50, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    _role=Depends(require_permission(Permission.AUDIT_READ)),
) -> AuditListResponse:
    """List audit log entries for the current tenant (newest first)."""
    base_filter = []
    if actor_id:
        base_filter.append(AuditLog.actor_id == actor_id)
    if action:
        base_filter.append(AuditLog.action == action)
    if outcome:
        base_filter.append(AuditLog.outcome == outcome.upper())

    count_result = await db.execute(select(func.count()).select_from(AuditLog).where(*base_filter))
    total: int = count_result.scalar_one()

    query = (
        select(AuditLog)
        .where(*base_filter)
        .order_by(desc(AuditLog.occurred_at))
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(query)
    entries = [
        AuditEntry(
            id=e.id, actor_id=e.actor_id, actor_role=e.actor_role,
            action=e.action, resource_type=e.resource_type,
            resource_id=e.resource_id, outcome=e.outcome,
            occurred_at=e.occurred_at,
        )
        for e in result.scalars()
    ]
    return AuditListResponse(entries=entries, total=total)
