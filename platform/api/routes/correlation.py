# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Correlation analysis endpoints — Claude Opus 4.6 agentic loop."""

import json
import logging

import anthropic
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..correlation.agent import run_correlation_agent
from ..correlation.models import CorrelationResult
from ..database import get_tenant_session
from ..middleware.rbac import Permission, Role, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()


class RootCauseRequest(BaseModel):
    context_hours: int = 168  # additional context window for the narrative


# ─── POST /analyze ────────────────────────────────────────────────────────────


@router.post(
    "/analyze",
    response_model=CorrelationResult,
    status_code=status.HTTP_200_OK,
)
async def analyze_incidents(
    request: Request,
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INCIDENTS_READ)),
) -> CorrelationResult:
    """
    Run the Claude Opus 4.6 correlation agent against all recent tenant incidents.
    Identifies multi-incident attack patterns and kill-chain progressions.
    May take 30–120 seconds depending on incident volume.
    """
    tenant_id = getattr(request.state, "tenant_id", None) or "dev_tenant"

    try:
        result = await run_correlation_agent(tenant_id=tenant_id, db=db)
    except Exception as exc:
        logger.error("Correlation agent failed for tenant %s: %s", tenant_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Correlation analysis failed",
        )

    return result


# ─── POST /incidents/{incident_id}/root-cause ─────────────────────────────────


@router.post(
    "/incidents/{incident_id}/root-cause",
    status_code=status.HTTP_200_OK,
    response_class=StreamingResponse,
)
async def stream_root_cause(
    incident_id: str = Path(...),
    body: RootCauseRequest = Body(RootCauseRequest()),
    request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INCIDENTS_READ)),
) -> StreamingResponse:
    """
    Stream a Claude-generated root-cause narrative for a specific incident
    as Server-Sent Events.  Each SSE event is: ``data: {"chunk": "<text>"}``

    The stream ends with: ``data: {"done": true}``
    """
    from sqlalchemy import select
    from ..models.incident import Incident
    import os

    tenant_id = getattr(request.state, "tenant_id", None) if request else None
    tenant_id = tenant_id or "dev_tenant"

    # Fetch the incident
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    api_key = os.getenv("ANTHROPIC_API_KEY")

    async def event_stream():
        if not api_key:
            yield 'data: {"chunk": "Root-cause analysis not available (ANTHROPIC_API_KEY not configured)."}\n\n'
            yield 'data: {"done": true}\n\n'
            return

        client = anthropic.AsyncAnthropic(api_key=api_key)
        prompt = (
            f"Perform a root-cause analysis for the following security incident:\n\n"
            f"ID: {incident.id}\n"
            f"Host: {incident.hostname}\n"
            f"Rule: {incident.rule_name} ({incident.rule_id})\n"
            f"Severity: {incident.severity}\n"
            f"MITRE Techniques: {', '.join(incident.mitre_techniques or [])}\n"
            f"First Seen: {incident.first_seen_at.isoformat()}\n"
            f"Status: {incident.status}\n\n"
            "Provide a detailed root-cause analysis covering:\n"
            "1. Likely initial access vector\n"
            "2. Attack progression and techniques observed\n"
            "3. Potential business impact\n"
            "4. Recommended immediate containment actions\n"
            "5. Long-term remediation steps\n"
        )

        try:
            async with client.messages.stream(
                model="claude-opus-4-6",
                max_tokens=2048,
                thinking={"type": "adaptive"},
                system=(
                    "You are an expert incident responder performing root-cause analysis "
                    "for a security operations center. Provide clear, actionable analysis."
                ),
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                async for event in stream:
                    if (
                        hasattr(event, "type")
                        and event.type == "content_block_delta"
                        and hasattr(event, "delta")
                        and hasattr(event.delta, "type")
                        and event.delta.type == "text_delta"
                    ):
                        chunk = event.delta.text.replace("\n", "\\n")
                        yield f'data: {json.dumps({"chunk": event.delta.text})}\n\n'
        except Exception as exc:
            logger.error("Root-cause stream failed for incident %s: %s", incident_id, exc)
            yield f'data: {json.dumps({"error": "Stream error occurred"})}\n\n'

        yield 'data: {"done": true}\n\n'

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
