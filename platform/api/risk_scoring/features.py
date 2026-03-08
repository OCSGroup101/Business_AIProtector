# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Feature extraction for endpoint risk scoring."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.incident import Incident


async def extract_agent_features(
    agent_id: str,
    hostname: str,
    db: AsyncSession,
) -> dict[str, float]:
    """
    Extract risk features for a single agent.

    Returns a dict of feature name → float value suitable for
    XGBoost inference or the heuristic fallback scorer.
    """
    now = datetime.now(tz=timezone.utc)
    window_7d = now - timedelta(days=7)
    window_30d = now - timedelta(days=30)
    window_1d = now - timedelta(days=1)

    # Total incidents in past 7 days
    r7 = await db.execute(
        select(func.count()).where(
            Incident.agent_id == agent_id,
            Incident.first_seen_at >= window_7d,
        )
    )
    incidents_7d = float(r7.scalar_one() or 0)

    # Total incidents in past 30 days
    r30 = await db.execute(
        select(func.count()).where(
            Incident.agent_id == agent_id,
            Incident.first_seen_at >= window_30d,
        )
    )
    incidents_30d = float(r30.scalar_one() or 0)

    # Critical/High severity in past 7 days
    rh = await db.execute(
        select(func.count()).where(
            Incident.agent_id == agent_id,
            Incident.first_seen_at >= window_7d,
            Incident.severity.in_(["CRITICAL", "HIGH"]),
        )
    )
    high_severity_7d = float(rh.scalar_one() or 0)

    # Unique rules triggered in past 7 days
    rr = await db.execute(
        select(func.count(func.distinct(Incident.rule_id))).where(
            Incident.agent_id == agent_id,
            Incident.first_seen_at >= window_7d,
        )
    )
    unique_rules_7d = float(rr.scalar_one() or 0)

    # Incidents in last 24 hours (recency spike)
    r1 = await db.execute(
        select(func.count()).where(
            Incident.agent_id == agent_id,
            Incident.first_seen_at >= window_1d,
        )
    )
    incidents_1d = float(r1.scalar_one() or 0)

    # Open incidents (unresolved)
    ro = await db.execute(
        select(func.count()).where(
            Incident.agent_id == agent_id,
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
        )
    )
    open_incidents = float(ro.scalar_one() or 0)

    # Recency spike ratio: incidents_1d / (incidents_7d / 7 + 1)
    daily_avg = incidents_7d / 7.0 + 1.0
    recency_spike = incidents_1d / daily_avg

    return {
        "incidents_7d": incidents_7d,
        "incidents_30d": incidents_30d,
        "high_severity_7d": high_severity_7d,
        "unique_rules_7d": unique_rules_7d,
        "incidents_1d": incidents_1d,
        "open_incidents": open_incidents,
        "recency_spike": recency_spike,
    }
