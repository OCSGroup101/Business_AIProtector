# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Endpoint risk scoring endpoints."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_tenant_session
from ..middleware.rbac import Permission, Role, require_permission
from ..models.agent import Agent
from ..risk_scoring.features import extract_agent_features
from ..risk_scoring.scorer import score_agent

logger = logging.getLogger(__name__)

router = APIRouter()


class AgentRiskScore(BaseModel):
    agent_id: str
    hostname: str
    risk_score: float
    risk_tier: str  # LOW | MEDIUM | HIGH | CRITICAL
    features: dict
    scored_at: datetime


@router.get(
    "/agents/{agent_id}/risk-score",
    response_model=AgentRiskScore,
    status_code=status.HTTP_200_OK,
)
async def get_agent_risk_score(
    agent_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.AGENTS_READ)),
) -> AgentRiskScore:
    """Return the current risk score for a single agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )

    features = await extract_agent_features(agent.id, agent.hostname, db)
    score, tier = score_agent(features)

    return AgentRiskScore(
        agent_id=agent.id,
        hostname=agent.hostname,
        risk_score=round(score, 4),
        risk_tier=tier,
        features=features,
        scored_at=datetime.now(tz=timezone.utc),
    )


@router.get(
    "/agents/risk-scores",
    response_model=list[AgentRiskScore],
    status_code=status.HTTP_200_OK,
)
async def list_agent_risk_scores(
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.AGENTS_READ)),
) -> list[AgentRiskScore]:
    """
    Return risk scores for all active agents, sorted by score descending.
    Useful for identifying the highest-risk endpoints at a glance.
    """
    result = await db.execute(
        select(Agent).where(Agent.is_active == True).limit(500)  # noqa: E712
    )
    agents = result.scalars().all()

    scored: list[AgentRiskScore] = []
    now = datetime.now(tz=timezone.utc)

    for agent in agents:
        features = await extract_agent_features(agent.id, agent.hostname, db)
        score, tier = score_agent(features)
        scored.append(
            AgentRiskScore(
                agent_id=agent.id,
                hostname=agent.hostname,
                risk_score=round(score, 4),
                risk_tier=tier,
                features=features,
                scored_at=now,
            )
        )

    scored.sort(key=lambda x: x.risk_score, reverse=True)
    return scored
