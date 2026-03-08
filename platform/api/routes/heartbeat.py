# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Agent heartbeat endpoint."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..command_queue import pop_commands
from ..database import get_tenant_session
from ..models.agent import Agent
from ..models.deployment import Deployment
from ..models.policy import Policy

# Trigger cert renewal when less than this many seconds remain
CERT_RENEW_THRESHOLD_SECS = 86_400  # 24 hours

logger = logging.getLogger(__name__)

router = APIRouter()


def _safe(value: object) -> str:
    """Strip newlines from a value before logging to prevent log injection."""
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


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


class DeploymentInfo(BaseModel):
    version: str
    binary_url: str
    sha256: str
    signature_url: str
    channel: str


class HeartbeatResponse(BaseModel):
    policy_update_version: Optional[int] = None
    commands: list[PlatformCommand] = []
    deployment: Optional[DeploymentInfo] = None


@router.post("/{agent_id}/heartbeat", response_model=HeartbeatResponse)
async def agent_heartbeat(
    agent_id: str = Path(...),
    request: HeartbeatRequest = Body(...),
    db: AsyncSession = Depends(get_tenant_session),
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found"
        )

    # Update heartbeat data
    agent.last_heartbeat_at = datetime.utcnow()
    agent.last_heartbeat_metrics = request.metrics.model_dump()
    agent.state = request.state
    agent.agent_version = request.agent_version

    await db.flush()

    raw_commands = await pop_commands(agent_id)
    commands = [
        PlatformCommand(
            type=c["type"], payload={k: v for k, v in c.items() if k != "type"}
        )
        for c in raw_commands
    ]

    # Queue cert renewal if expiry is within the threshold
    now = datetime.now(timezone.utc)
    if agent.cert_expires_at:
        expires_at = agent.cert_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        secs_remaining = (expires_at - now).total_seconds()
        if secs_remaining < CERT_RENEW_THRESHOLD_SECS:
            commands.append(PlatformCommand(type="renew_cert", payload=None))
            logger.info(
                "Agent %s cert expires in %.0fs — queuing renew_cert",
                _safe(agent_id),
                secs_remaining,
            )

    # Notify agent if a newer policy version is available
    policy_update_version: Optional[int] = None
    pol_result = await db.execute(
        select(Policy)
        .where(Policy.is_default.is_(True), Policy.is_active.is_(True))
        .order_by(Policy.version.desc())
        .limit(1)
    )
    current_policy = pol_result.scalar_one_or_none()
    if current_policy and current_policy.version > request.policy_version:
        policy_update_version = current_policy.version

    # Check for a pending deployment targeting this agent's OS/channel
    deployment_info: Optional[DeploymentInfo] = None
    dep_query = (
        select(Deployment)
        .where(
            Deployment.status == "rolling_out",
        )
        .order_by(Deployment.created_at.desc())
        .limit(1)
    )
    dep_result = await db.execute(dep_query)
    pending_dep = dep_result.scalar_one_or_none()
    if pending_dep is not None:
        # Only include if the deployment targets this agent's OS (or all OSes)
        dep_os = pending_dep.target_os
        if dep_os is None or dep_os == agent.os_platform:
            # Only push if the agent is not already on this version
            if agent.agent_version != pending_dep.version:
                deployment_info = DeploymentInfo(
                    version=pending_dep.version,
                    binary_url=pending_dep.binary_url,
                    sha256=pending_dep.binary_sha256,
                    signature_url=pending_dep.signature_url,
                    channel=pending_dep.channel,
                )

    logger.debug(
        "Heartbeat received from agent %s (state: %s, commands: %d, deployment: %s)",
        _safe(agent_id),
        _safe(request.state),
        len(commands),
        deployment_info.version if deployment_info else "none",
    )

    return HeartbeatResponse(
        policy_update_version=policy_update_version,
        commands=commands,
        deployment=deployment_info,
    )
