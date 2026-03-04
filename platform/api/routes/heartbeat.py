"""Agent heartbeat endpoint."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..models.agent import Agent

logger = logging.getLogger(__name__)

router = APIRouter()


class HealthMetrics(BaseModel):
    cpu_percent: float = 0.0
    ram_mb: int = 0
    ring_buffer_fill_pct: int = 0
    events_processed_since_last_heartbeat: int = 0


class HeartbeatRequest(BaseModel):
    agent_id: str
    agent_version: str
    state: str
    policy_version: int
    metrics: HealthMetrics


class PlatformCommand(BaseModel):
    type: str
    payload: Optional[dict] = None


class HeartbeatResponse(BaseModel):
    policy_update_version: Optional[int] = None
    commands: list[PlatformCommand] = []


@router.post("/{agent_id}/heartbeat", response_model=HeartbeatResponse)
async def agent_heartbeat(
    agent_id: str = Path(...),
    request: HeartbeatRequest = ...,
    db: AsyncSession = Depends(get_db),
) -> HeartbeatResponse:
    """
    Process an agent heartbeat.
    Updates the agent's last_seen timestamp and health metrics.
    Returns any pending commands or policy update notifications.
    """
    # Look up agent
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()

    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    # Update heartbeat data
    agent.last_heartbeat_at = datetime.utcnow()
    agent.last_heartbeat_metrics = request.metrics.model_dump()
    agent.state = request.state
    agent.agent_version = request.agent_version

    await db.flush()

    # Check for policy updates
    policy_update_version: Optional[int] = None
    # Phase 1: Compare agent.policy_version vs current policy version for tenant
    # if current_version > request.policy_version: policy_update_version = current_version

    commands: list[PlatformCommand] = []
    # Phase 1: Check command queue in Redis for this agent

    logger.debug("Heartbeat received from agent %s (state: %s)", agent_id, request.state)

    return HeartbeatResponse(
        policy_update_version=policy_update_version,
        commands=commands,
    )
