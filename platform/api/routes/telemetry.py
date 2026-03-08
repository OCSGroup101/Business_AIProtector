# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Telemetry ingestion endpoint — accepts NDJSON batches from agents.

Flow:
  1. Agent POSTs NDJSON to /api/v1/telemetry/batch
     Headers: X-Agent-ID, X-Tenant-ID
  2. Platform parses each event line
  3. For each event that has a non-empty `detections` list, create/update
     an incident via incident_service
  4. Return 202 with accepted/errors/incidents_created counts
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_tenant_session
from ..incident_service import create_or_update_incident

logger = logging.getLogger(__name__)

router = APIRouter()


def _safe(value: object) -> str:
    """Strip newlines from a value before logging to prevent log injection."""
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_telemetry_batch(
    request: Request,
    x_agent_id: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_tenant_session),
) -> dict:
    """
    Ingest a batch of telemetry events from an agent (NDJSON, one JSON object per line).

    Events that contain a non-empty `detections` array trigger incident creation.
    All other events are accepted and acknowledged (Kafka forwarding in Phase 2).
    """
    body = await request.body()
    if not body:
        return {"accepted": 0, "errors": 0, "incidents_created": 0}

    lines = body.decode("utf-8", errors="replace").strip().splitlines()
    events: list[dict] = []
    parse_errors = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            parse_errors += 1

    if parse_errors > 0:
        logger.warning(
            "Agent %s: %d malformed telemetry lines in batch of %d",
            _safe(x_agent_id),
            parse_errors,
            len(lines),
        )

    # Determine tenant_id and agent hostname from events / headers
    tenant_id = x_tenant_id or request.state.__dict__.get("tenant_id", "")
    incidents_created = 0
    incidents_updated = 0

    for event in events:
        detections = event.get("detections") or []
        if not detections:
            continue

        agent_id = event.get("agent_id") or x_agent_id or "unknown"
        hostname = event.get("hostname") or event.get("host") or agent_id

        for detection in detections:
            try:
                result = await create_or_update_incident(
                    db=db,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    hostname=hostname,
                    detection=detection,
                    raw_event=event,
                )
                if result:
                    _, is_new = result
                    if is_new:
                        incidents_created += 1
                    else:
                        incidents_updated += 1
            except Exception:
                logger.exception(
                    "Failed to create/update incident for agent=%s rule=%s",
                    _safe(agent_id),
                    _safe(detection.get("rule_id")),
                )

    logger.info(
        "Telemetry batch: agent=%s events=%d errors=%d incidents_created=%d incidents_updated=%d",
        _safe(x_agent_id),
        len(events),
        parse_errors,
        incidents_created,
        incidents_updated,
    )

    return {
        "accepted": len(events),
        "errors": parse_errors,
        "incidents_created": incidents_created,
        "incidents_updated": incidents_updated,
    }
