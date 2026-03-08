# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Pydantic models mirroring the OpenClaw platform API response shapes.
Used for type-safe access to API responses in integration code.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────────────────

IncidentStatus = Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
AgentStatus = Literal["active", "isolated", "offline", "enrolling"]


# ── Incident ───────────────────────────────────────────────────────────────────

class Incident(BaseModel):
    id: str
    tenant_id: str
    agent_id: str
    hostname: str
    rule_id: str
    rule_name: str
    severity: Severity
    status: IncidentStatus
    mitre_techniques: list[str] = Field(default_factory=list)
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    summary: Optional[str] = None

    def is_active(self) -> bool:
        return self.status in ("OPEN", "INVESTIGATING", "CONTAINED")

    def to_siem_dict(self) -> dict[str, Any]:
        """Flatten incident to a SIEM-friendly dictionary."""
        return {
            "openclaw_incident_id": self.id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "status": self.status,
            "mitre_techniques": ",".join(self.mitre_techniques),
            "first_seen_at": self.first_seen_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "assigned_to": self.assigned_to,
        }


# ── Agent ──────────────────────────────────────────────────────────────────────

class Agent(BaseModel):
    agent_id: str
    tenant_id: str
    hostname: str
    os_info: dict[str, Any] = Field(default_factory=dict)
    status: AgentStatus
    last_seen_at: Optional[datetime] = None
    enrolled_at: Optional[datetime] = None
    agent_version: Optional[str] = None


# ── Policy ─────────────────────────────────────────────────────────────────────

class Policy(BaseModel):
    id: str
    tenant_id: str
    name: str
    content_toml: str
    created_at: datetime
    updated_at: datetime


# ── Audit ──────────────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    id: str
    actor_id: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    outcome: str
    occurred_at: datetime


# ── Telemetry ─────────────────────────────────────────────────────────────────

class Detection(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    mitre_techniques: list[str] = Field(default_factory=list)


class TelemetryEvent(BaseModel):
    event_id: str
    agent_id: str
    tenant_id: str
    hostname: str
    event_type: str
    timestamp: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
    detections: list[Detection] = Field(default_factory=list)

    def to_ndjson_line(self) -> str:
        """Serialize to a single NDJSON line for batch upload."""
        import json
        return json.dumps(self.model_dump(mode="json"))


# ── IOC ───────────────────────────────────────────────────────────────────────

class IocEntry(BaseModel):
    action: Literal["upsert", "delete"]
    type: str
    value: str
    score: Optional[float] = None
    metadata: Optional[dict[str, Any]] = None
