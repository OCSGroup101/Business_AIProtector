"""Incident management endpoints."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from ..database import get_tenant_session
from ..models.incident import Incident, IncidentEvent
from ..middleware.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()


class IncidentSummary(BaseModel):
    id: str
    agent_id: str
    hostname: str
    rule_name: str
    severity: str
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    mitre_techniques: Optional[list] = None


class IncidentDetail(IncidentSummary):
    summary: Optional[str] = None
    containment_status: Optional[str] = None
    containment_actions: Optional[list] = None
    events: list[dict] = []


class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


@router.get("", response_model=list[IncidentSummary])
async def list_incidents(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.INCIDENTS_READ)),
) -> list[IncidentSummary]:
    """List incidents for the current tenant, optionally filtered."""
    query = (
        select(Incident)
        .order_by(desc(Incident.first_seen_at))
        .limit(limit)
        .offset(offset)
    )

    if severity:
        query = query.where(Incident.severity == severity.upper())
    if status:
        query = query.where(Incident.status == status.upper())
    if agent_id:
        query = query.where(Incident.agent_id == agent_id)

    result = await db.execute(query)
    incidents = result.scalars().all()

    return [
        IncidentSummary(
            id=i.id,
            agent_id=i.agent_id,
            hostname=i.hostname,
            rule_name=i.rule_name,
            severity=i.severity,
            status=i.status,
            first_seen_at=i.first_seen_at,
            last_seen_at=i.last_seen_at,
            mitre_techniques=i.mitre_techniques,
        )
        for i in incidents
    ]


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.INCIDENTS_READ)),
) -> IncidentDetail:
    """Get full incident details including timeline events."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found"
        )

    events_result = await db.execute(
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.occurred_at)
    )
    events = [
        {
            "event_id": e.event_id,
            "event_type": e.event_type,
            "occurred_at": e.occurred_at.isoformat(),
            **e.event_json,
        }
        for e in events_result.scalars()
    ]

    return IncidentDetail(
        id=incident.id,
        agent_id=incident.agent_id,
        hostname=incident.hostname,
        rule_name=incident.rule_name,
        severity=incident.severity,
        status=incident.status,
        first_seen_at=incident.first_seen_at,
        last_seen_at=incident.last_seen_at,
        mitre_techniques=incident.mitre_techniques,
        summary=incident.summary,
        containment_status=incident.containment_status,
        containment_actions=incident.containment_actions,
        events=events,
    )


@router.patch("/{incident_id}", response_model=IncidentSummary)
async def update_incident(
    incident_id: str = Path(...),
    request: UpdateIncidentRequest = ...,
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.INCIDENTS_WRITE)),
) -> IncidentSummary:
    """Update incident status or assignment."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found"
        )

    if request.status:
        valid_statuses = {
            "OPEN",
            "INVESTIGATING",
            "CONTAINED",
            "RESOLVED",
            "FALSE_POSITIVE",
        }
        if request.status.upper() not in valid_statuses:
            raise HTTPException(
                status_code=400, detail=f"Invalid status: {request.status}"
            )
        incident.status = request.status.upper()
        if request.status.upper() == "RESOLVED":
            incident.resolved_at = datetime.utcnow()

    if request.assigned_to:
        incident.assigned_to = request.assigned_to

    await db.flush()
    return IncidentSummary(
        id=incident.id,
        agent_id=incident.agent_id,
        hostname=incident.hostname,
        rule_name=incident.rule_name,
        severity=incident.severity,
        status=incident.status,
        first_seen_at=incident.first_seen_at,
        last_seen_at=incident.last_seen_at,
        mitre_techniques=incident.mitre_techniques,
    )
