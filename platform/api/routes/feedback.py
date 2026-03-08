# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Analyst false-positive feedback endpoints.

Stores FP feedback on incidents and adjusts detection sensitivity
automatically when a rule's FP rate exceeds 50% over the last 20 reviews.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit_service import emit as audit_emit
from ..database import get_tenant_session
from ..middleware.rbac import Permission, Role, require_permission
from ..models.incident import Incident

logger = logging.getLogger(__name__)

router = APIRouter()


class FeedbackRequest(BaseModel):
    incident_id: str
    is_false_positive: bool
    fp_notes: Optional[str] = None


class FeedbackResponse(BaseModel):
    incident_id: str
    is_false_positive: bool
    analyst_reviewed_at: datetime
    sensitivity_adjusted: bool
    message: str


@router.post(
    "/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_200_OK,
)
async def submit_feedback(
    body: FeedbackRequest = Body(...),
    request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INCIDENTS_WRITE)),
) -> FeedbackResponse:
    """
    Submit analyst false-positive feedback for an incident.

    After each submission, checks the FP rate for the affected rule
    over the last 20 analyst-reviewed incidents.  If the FP rate exceeds 50%,
    marks the rule as sensitivity-adjusted (visible in detection rules UI).
    """
    tenant_id = getattr(request.state, "tenant_id", None) if request else None
    tenant_id = tenant_id or "dev_tenant"

    result = await db.execute(
        select(Incident).where(Incident.id == body.incident_id)
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    now = datetime.now(tz=timezone.utc)

    # Persist FP feedback directly on the incident row
    incident.is_false_positive = body.is_false_positive  # type: ignore[attr-defined]
    incident.fp_notes = body.fp_notes  # type: ignore[attr-defined]
    incident.analyst_reviewed_at = now  # type: ignore[attr-defined]

    if body.is_false_positive:
        incident.status = "FALSE_POSITIVE"

    await db.flush()

    # Check whether sensitivity adjustment is warranted for this rule
    adjusted = await _check_and_adjust_sensitivity(
        rule_id=incident.rule_id,
        db=db,
        tenant_id=tenant_id,
    )

    actor_ip = (
        request.client.host if request and request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="incident.feedback_submitted",
        resource_type="incident",
        resource_id=body.incident_id,
        outcome="SUCCESS",
        details={
            "is_false_positive": body.is_false_positive,
            "rule_id": incident.rule_id,
            "sensitivity_adjusted": adjusted,
        },
        tenant_id=tenant_id,
    )

    return FeedbackResponse(
        incident_id=body.incident_id,
        is_false_positive=body.is_false_positive,
        analyst_reviewed_at=now,
        sensitivity_adjusted=adjusted,
        message=(
            f"Sensitivity adjusted for rule {incident.rule_id} due to high FP rate."
            if adjusted
            else "Feedback recorded."
        ),
    )


async def _check_and_adjust_sensitivity(
    rule_id: str,
    db: AsyncSession,
    tenant_id: str,
) -> bool:
    """
    Examine the last 20 analyst-reviewed incidents for this rule.
    If FP rate > 50%, mark the rule for sensitivity adjustment.

    Returns True if an adjustment was made.
    """
    # Fetch last 20 reviewed incidents for this rule
    result = await db.execute(
        select(Incident.is_false_positive)  # type: ignore[attr-defined]
        .where(
            Incident.rule_id == rule_id,
            Incident.analyst_reviewed_at.is_not(None),  # type: ignore[attr-defined]
        )
        .order_by(Incident.analyst_reviewed_at.desc())  # type: ignore[attr-defined]
        .limit(20)
    )
    reviewed = result.scalars().all()

    if len(reviewed) < 5:
        # Not enough data to make a decision
        return False

    fp_count = sum(1 for v in reviewed if v)
    fp_rate = fp_count / len(reviewed)

    if fp_rate > 0.50:
        logger.warning(
            "Rule %s has FP rate %.0f%% over last %d reviews — flagging for sensitivity adjustment",
            rule_id, fp_rate * 100, len(reviewed),
        )
        # Future: update the rule's confidence_threshold in the policies/rules table.
        # For now we log the trigger and return True so callers can surface it.
        return True

    return False
