# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Pydantic schemas for correlation analysis results."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CorrelationInsight(BaseModel):
    pattern_type: str  # lateral_movement | persistence_chain | data_exfil | credential_theft | etc.
    affected_agents: list[str]
    incident_ids: list[str]
    mitre_techniques: list[str]
    confidence: float  # 0.0–1.0
    narrative: str
    recommended_actions: list[str]
    kill_chain_stage: Optional[str] = None


class CorrelationResult(BaseModel):
    tenant_id: str
    analyzed_at: datetime
    incidents_analyzed: int
    insights: list[CorrelationInsight]
    overall_threat_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    summary: str
