# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Tool definitions and implementations for the correlation agent."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.incident import Incident
from ..models.global_ioc import GlobalIocEntry

logger = logging.getLogger(__name__)

# ─── MITRE technique → kill-chain stage mapping ───────────────────────────────

_MITRE_STAGE_MAP: dict[str, str] = {
    "T1595": "reconnaissance",
    "T1592": "reconnaissance",
    "T1589": "reconnaissance",
    "T1590": "reconnaissance",
    "T1591": "reconnaissance",
    "T1598": "reconnaissance",
    "T1566": "initial_access",
    "T1190": "initial_access",
    "T1133": "initial_access",
    "T1200": "initial_access",
    "T1091": "initial_access",
    "T1195": "initial_access",
    "T1059": "execution",
    "T1203": "execution",
    "T1053": "execution",
    "T1569": "execution",
    "T1204": "execution",
    "T1047": "execution",
    "T1547": "persistence",
    "T1543": "persistence",
    "T1546": "persistence",
    "T1136": "persistence",
    "T1098": "persistence",
    "T1197": "persistence",
    "T1548": "privilege_escalation",
    "T1134": "privilege_escalation",
    "T1055": "privilege_escalation",
    "T1068": "privilege_escalation",
    "T1562": "defense_evasion",
    "T1070": "defense_evasion",
    "T1036": "defense_evasion",
    "T1027": "defense_evasion",
    "T1553": "defense_evasion",
    "T1112": "defense_evasion",
    "T1110": "credential_access",
    "T1003": "credential_access",
    "T1558": "credential_access",
    "T1555": "credential_access",
    "T1552": "credential_access",
    "T1087": "discovery",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1049": "discovery",
    "T1069": "discovery",
    "T1018": "discovery",
    "T1021": "lateral_movement",
    "T1080": "lateral_movement",
    "T1550": "lateral_movement",
    "T1560": "collection",
    "T1074": "collection",
    "T1114": "collection",
    "T1056": "collection",
    "T1113": "collection",
    "T1125": "collection",
    "T1041": "exfiltration",
    "T1020": "exfiltration",
    "T1048": "exfiltration",
    "T1011": "exfiltration",
    "T1567": "exfiltration",
    "T1485": "impact",
    "T1486": "impact",
    "T1490": "impact",
    "T1489": "impact",
    "T1498": "impact",
}

_KILL_CHAIN_ORDER = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact",
]

# ─── Tool definitions (Anthropic tool-use schema) ─────────────────────────────

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "query_recent_incidents",
        "description": (
            "Query recent incidents for the current tenant. Returns incident summaries "
            "including severity, MITRE techniques, affected hostnames, and timeline."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "Look-back window in hours (1–720). Default 168 (7 days).",
                },
                "severity_filter": {
                    "type": "string",
                    "description": "Optional severity filter: CRITICAL, HIGH, MEDIUM, LOW. Omit for all.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum incidents to return (1–500). Default 100.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_agent_timeline",
        "description": (
            "Return a chronological list of incidents for a specific agent hostname "
            "within a time window. Use to trace an attacker's path on one endpoint."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "The agent hostname to query.",
                },
                "hours": {
                    "type": "integer",
                    "description": "Look-back window in hours. Default 168.",
                },
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "lookup_ioc",
        "description": (
            "Look up a threat indicator (hash, IP, domain, URL) in the global IOC store. "
            "Returns threat score, type, and source feed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "The IOC value: file hash (MD5/SHA256), IP address, domain, or URL.",
                },
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "get_shared_iocs",
        "description": (
            "Given a list of incident IDs, find MITRE techniques and rule IDs that appear "
            "in multiple incidents — suggesting a coordinated campaign."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "incident_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of incident IDs to cross-reference.",
                },
            },
            "required": ["incident_ids"],
        },
    },
    {
        "name": "get_mitre_chain",
        "description": (
            "Given a list of MITRE technique IDs, map them to kill-chain stages, "
            "identify progression, and predict likely next-stage techniques."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "MITRE ATT&CK technique IDs, e.g. ['T1059.001', 'T1547.001'].",
                },
            },
            "required": ["techniques"],
        },
    },
]

# ─── Tool implementations ─────────────────────────────────────────────────────


async def _query_recent_incidents(
    hours: int, severity_filter: str | None, limit: int, db: AsyncSession
) -> dict[str, Any]:
    since = datetime.now(tz=timezone.utc) - timedelta(hours=max(1, min(hours, 720)))
    lim = max(1, min(limit, 500))

    q = select(Incident).where(Incident.first_seen_at >= since)
    if severity_filter:
        q = q.where(Incident.severity == severity_filter.upper())
    q = q.order_by(Incident.first_seen_at.desc()).limit(lim)

    result = await db.execute(q)
    incidents = result.scalars().all()

    return {
        "count": len(incidents),
        "incidents": [
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
        ],
    }


async def _get_agent_timeline(
    hostname: str, hours: int, db: AsyncSession
) -> dict[str, Any]:
    since = datetime.now(tz=timezone.utc) - timedelta(hours=max(1, min(hours, 720)))
    result = await db.execute(
        select(Incident)
        .where(Incident.hostname == hostname, Incident.first_seen_at >= since)
        .order_by(Incident.first_seen_at.asc())
        .limit(200)
    )
    incidents = result.scalars().all()
    return {
        "hostname": hostname,
        "count": len(incidents),
        "timeline": [
            {
                "id": inc.id,
                "rule_id": inc.rule_id,
                "rule_name": inc.rule_name,
                "severity": inc.severity,
                "mitre_techniques": inc.mitre_techniques or [],
                "first_seen_at": inc.first_seen_at.isoformat(),
            }
            for inc in incidents
        ],
    }


async def _lookup_ioc(indicator: str, db: AsyncSession) -> dict[str, Any]:
    result = await db.execute(
        select(GlobalIocEntry).where(GlobalIocEntry.value == indicator).limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return {"found": False, "indicator": indicator}
    return {
        "found": True,
        "indicator": indicator,
        "ioc_type": row.ioc_type,
        "score": row.score,
        "source": row.sources,
        "tags": row.tags or [],
    }


async def _get_shared_iocs(incident_ids: list[str], db: AsyncSession) -> dict[str, Any]:
    if not incident_ids:
        return {"shared_techniques": [], "shared_rules": []}

    result = await db.execute(select(Incident).where(Incident.id.in_(incident_ids)))
    incidents = result.scalars().all()

    from collections import Counter

    technique_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()

    for inc in incidents:
        for t in inc.mitre_techniques or []:
            technique_counter[t] += 1
        rule_counter[inc.rule_id] += 1

    shared_techniques = [t for t, c in technique_counter.items() if c > 1]
    shared_rules = [r for r, c in rule_counter.items() if c > 1]

    return {
        "incidents_checked": len(incidents),
        "shared_techniques": shared_techniques,
        "shared_rules": shared_rules,
        "technique_counts": dict(technique_counter.most_common(20)),
        "rule_counts": dict(rule_counter.most_common(20)),
    }


def _get_mitre_chain(techniques: list[str]) -> dict[str, Any]:
    # Normalize: strip sub-technique suffix for stage lookup
    def base_id(t: str) -> str:
        return t.split(".")[0]

    stages_seen: set[str] = set()
    for t in techniques:
        stage = _MITRE_STAGE_MAP.get(base_id(t))
        if stage:
            stages_seen.add(stage)

    ordered_stages = [s for s in _KILL_CHAIN_ORDER if s in stages_seen]

    # Predict next stage
    next_stage = None
    if ordered_stages:
        last_idx = _KILL_CHAIN_ORDER.index(ordered_stages[-1])
        if last_idx + 1 < len(_KILL_CHAIN_ORDER):
            next_stage = _KILL_CHAIN_ORDER[last_idx + 1]

    return {
        "techniques_mapped": len(stages_seen),
        "kill_chain_stages": ordered_stages,
        "highest_stage": ordered_stages[-1] if ordered_stages else None,
        "predicted_next_stage": next_stage,
        "progression_pct": round(len(ordered_stages) / len(_KILL_CHAIN_ORDER) * 100, 1),
    }


async def execute_tool(
    tool_name: str,
    tool_input: dict[str, Any],
    db: AsyncSession,
    tenant_id: str,
) -> Any:
    """Dispatch a tool call from the correlation agent."""
    try:
        if tool_name == "query_recent_incidents":
            return await _query_recent_incidents(
                hours=tool_input.get("hours", 168),
                severity_filter=tool_input.get("severity_filter"),
                limit=tool_input.get("limit", 100),
                db=db,
            )
        elif tool_name == "get_agent_timeline":
            return await _get_agent_timeline(
                hostname=tool_input["hostname"],
                hours=tool_input.get("hours", 168),
                db=db,
            )
        elif tool_name == "lookup_ioc":
            return await _lookup_ioc(
                indicator=tool_input["indicator"],
                db=db,
            )
        elif tool_name == "get_shared_iocs":
            return await _get_shared_iocs(
                incident_ids=tool_input.get("incident_ids", []),
                db=db,
            )
        elif tool_name == "get_mitre_chain":
            return _get_mitre_chain(tool_input.get("techniques", []))
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    except Exception as exc:
        logger.error("Tool %s failed: %s", tool_name, exc)
        return {"error": str(exc)}
