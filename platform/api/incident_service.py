# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Incident creation and deduplication service.

Dedup rule: if an OPEN or INVESTIGATING incident exists for the same
(agent_id, rule_id) within a 24-hour window, append the new event to the
existing incident rather than creating a new one.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models.incident import Incident, IncidentEvent

logger = logging.getLogger(__name__)

_DEDUP_WINDOW = timedelta(hours=24)


def _safe(value: object) -> str:
    """Strip newlines from a value before logging to prevent log injection."""
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


_OPEN_STATUSES = ("OPEN", "INVESTIGATING")


def _make_incident_id(agent_id: str, rule_id: str, ts: datetime) -> str:
    """Stable short ID: first 20 hex chars of SHA-256(agent_id + rule_id + minute)."""
    minute_str = ts.strftime("%Y%m%d%H%M")
    raw = hashlib.sha256(f"{agent_id}:{rule_id}:{minute_str}".encode()).hexdigest()
    return raw[:20]


def _make_event_id(event: dict) -> str:
    raw = event.get("event_id") or event.get("id") or ""
    if raw:
        return raw[:30]
    # Fallback: hash the event dict
    return hashlib.sha256(str(event).encode()).hexdigest()[:30]


async def create_or_update_incident(
    db: AsyncSession,
    tenant_id: str,
    agent_id: str,
    hostname: str,
    detection: dict,
    raw_event: dict,
) -> Optional[tuple[str, bool]]:
    """
    Upsert an incident from a detection hit.

    `detection` dict shape (from TelemetryEvent.detections[]):
      {
        "rule_id":         "OC-IOC-0001",
        "rule_name":       "Known-bad file hash",
        "severity":        "HIGH",
        "mitre_techniques": ["T1059"],
      }

    `raw_event` is the full TelemetryEvent dict.

    Returns (incident_id, is_new) on success, None on failure.
    is_new is True when a new incident was created, False when an existing one was updated.
    """
    rule_id = detection.get("rule_id", "unknown")
    rule_name = detection.get("rule_name", rule_id)
    severity = detection.get("severity", "MEDIUM")
    mitre = detection.get("mitre_techniques") or []

    now = datetime.now(tz=timezone.utc)
    dedup_cutoff = now - _DEDUP_WINDOW

    # Look for an existing open incident within the dedup window
    existing = await db.execute(
        select(Incident)
        .where(
            and_(
                Incident.agent_id == agent_id,
                Incident.rule_id == rule_id,
                Incident.status.in_(_OPEN_STATUSES),
                Incident.first_seen_at >= dedup_cutoff,
            )
        )
        .limit(1)
    )
    incident = existing.scalar_one_or_none()

    is_new = incident is None
    if is_new:
        # Create new incident
        incident_id = _make_incident_id(agent_id, rule_id, now)
        incident = Incident(
            id=incident_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            hostname=hostname,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            mitre_techniques=mitre,
            status="OPEN",
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(incident)
        logger.info(
            "New incident created: id=%s agent=%s rule=%s severity=%s",
            _safe(incident_id),
            _safe(agent_id),
            _safe(rule_id),
            _safe(severity),
        )
    else:
        # Update existing — bump last_seen and escalate severity if higher
        incident.last_seen_at = now
        _severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if _severity_rank.get(severity, 0) > _severity_rank.get(incident.severity, 0):
            incident.severity = severity
        # Merge new MITRE techniques
        existing_mitre = set(incident.mitre_techniques or [])
        incident.mitre_techniques = list(existing_mitre | set(mitre))

    # Append the individual event to the incident timeline
    event_id = _make_event_id(raw_event)

    # Guard against duplicate event IDs (idempotent re-upload)
    dup_check = await db.execute(
        select(IncidentEvent).where(IncidentEvent.event_id == event_id).limit(1)
    )
    if dup_check.scalar_one_or_none() is None:
        occurred_str = raw_event.get("timestamp") or raw_event.get("occurred_at")
        try:
            occurred_at = datetime.fromisoformat(occurred_str) if occurred_str else now
            if occurred_at.tzinfo is None:
                occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            occurred_at = now

        ie = IncidentEvent(
            incident_id=incident.id,
            event_id=event_id,
            event_type=raw_event.get("event_type", "unknown"),
            event_json=raw_event,
            occurred_at=occurred_at,
        )
        db.add(ie)

    return incident.id, is_new
