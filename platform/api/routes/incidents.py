"""Incident management endpoints."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from ..database import get_tenant_session
from ..models.incident import Incident, IncidentEvent
from ..middleware.rbac import Permission, require_permission, Role
from ..audit_service import emit as audit_emit

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
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None


class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


class ResolveIncidentRequest(BaseModel):
    resolution_notes: Optional[str] = None


class AssignIncidentRequest(BaseModel):
    assigned_to: str


class TimelineEvent(BaseModel):
    event_id: str
    event_type: str
    occurred_at: datetime
    details: dict


class TimelineResponse(BaseModel):
    events: list[TimelineEvent]
    next_cursor: Optional[str] = None
    total: int


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
        resolved_at=incident.resolved_at,
        assigned_to=incident.assigned_to,
    )


@router.patch("/{incident_id}", response_model=IncidentSummary)
async def update_incident(
    incident_id: str = Path(...),
    request: UpdateIncidentRequest = Body(...),
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


@router.post("/{incident_id}/resolve", response_model=IncidentSummary)
async def resolve_incident(
    incident_id: str = Path(...),
    body: ResolveIncidentRequest = Body(default=ResolveIncidentRequest()),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INCIDENTS_RESOLVE)),
) -> IncidentSummary:
    """Resolve an incident with optional resolution notes."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    incident.status = "RESOLVED"
    incident.resolved_at = datetime.now(tz=timezone.utc)
    if body.resolution_notes:
        incident.summary = body.resolution_notes

    await db.flush()

    tenant_id = getattr(http_request.state, "tenant_id", "unknown") if http_request else "unknown"
    actor_ip = http_request.client.host if http_request and http_request.client else None
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="incident.status_changed",
        resource_type="incident",
        resource_id=incident_id,
        outcome="SUCCESS",
        details={"new_status": "RESOLVED", "notes": body.resolution_notes},
        tenant_id=tenant_id,
    )

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


@router.post("/{incident_id}/assign", response_model=IncidentSummary)
async def assign_incident(
    incident_id: str = Path(...),
    body: AssignIncidentRequest = Body(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INCIDENTS_WRITE)),
) -> IncidentSummary:
    """Assign an incident to an analyst."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    incident.assigned_to = body.assigned_to
    await db.flush()

    tenant_id = getattr(http_request.state, "tenant_id", "unknown") if http_request else "unknown"
    actor_ip = http_request.client.host if http_request and http_request.client else None
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="incident.assigned",
        resource_type="incident",
        resource_id=incident_id,
        outcome="SUCCESS",
        details={"assigned_to": body.assigned_to},
        tenant_id=tenant_id,
    )

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


@router.get("/{incident_id}/timeline", response_model=TimelineResponse)
async def get_incident_timeline(
    incident_id: str = Path(...),
    cursor: Optional[str] = Query(None, description="ISO timestamp cursor for pagination"),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INCIDENTS_READ)),
) -> TimelineResponse:
    """Return paginated timeline events for an incident."""
    # Verify incident exists
    inc_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if inc_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    query = (
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.occurred_at)
        .limit(limit + 1)
    )
    if cursor:
        from sqlalchemy import cast
        from sqlalchemy.types import DateTime
        cursor_dt = datetime.fromisoformat(cursor)
        query = query.where(IncidentEvent.occurred_at > cursor_dt)

    result = await db.execute(query)
    rows = list(result.scalars().all())

    has_more = len(rows) > limit
    rows = rows[:limit]

    events = [
        TimelineEvent(
            event_id=e.event_id,
            event_type=e.event_type,
            occurred_at=e.occurred_at,
            details=e.event_json,
        )
        for e in rows
    ]

    # Count total
    from sqlalchemy import func
    count_result = await db.execute(
        select(func.count()).select_from(IncidentEvent).where(
            IncidentEvent.incident_id == incident_id
        )
    )
    total: int = count_result.scalar_one()

    next_cursor = rows[-1].occurred_at.isoformat() if has_more and rows else None

    return TimelineResponse(events=events, next_cursor=next_cursor, total=total)
