"""Agent management endpoints."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from ..command_queue import push_command
from ..database import get_tenant_session
from ..models.agent import Agent
from ..middleware.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()


class AgentSummary(BaseModel):
    id: str
    hostname: str
    os_platform: str
    os_version: str
    agent_version: str
    state: str
    last_heartbeat_at: Optional[datetime] = None
    policy_version: int = 0


class IsolateRequest(BaseModel):
    reason: str


@router.get("", response_model=list[AgentSummary])
async def list_agents(
    state: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.AGENTS_READ)),
) -> list[AgentSummary]:
    """List all agents for the current tenant."""
    query = (
        select(Agent)
        .where(Agent.is_active.is_(True))
        .order_by(desc(Agent.last_heartbeat_at))
        .limit(limit)
        .offset(offset)
    )
    if state:
        query = query.where(Agent.state == state.upper())

    result = await db.execute(query)
    return [
        AgentSummary(
            id=a.id,
            hostname=a.hostname,
            os_platform=a.os_platform,
            os_version=a.os_version,
            agent_version=a.agent_version,
            state=a.state,
            last_heartbeat_at=a.last_heartbeat_at,
            policy_version=a.policy_version,
        )
        for a in result.scalars()
    ]


@router.get("/{agent_id}", response_model=AgentSummary)
async def get_agent(
    agent_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.AGENTS_READ)),
) -> AgentSummary:
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found"
        )
    return AgentSummary(
        id=agent.id,
        hostname=agent.hostname,
        os_platform=agent.os_platform,
        os_version=agent.os_version,
        agent_version=agent.agent_version,
        state=agent.state,
        last_heartbeat_at=agent.last_heartbeat_at,
        policy_version=agent.policy_version,
    )


@router.post("/{agent_id}/isolate", status_code=status.HTTP_202_ACCEPTED)
async def isolate_agent(
    agent_id: str = Path(...),
    request: IsolateRequest = ...,
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.CONTAINMENT_APPLY)),
) -> dict:
    """Queue a host isolation command to be delivered on next heartbeat."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found"
        )

    await push_command(agent_id, {"type": "isolate", "reason": request.reason})
    logger.info(
        "Isolation command queued for agent %s (reason: %s)", agent_id, request.reason
    )
    return {"status": "queued", "agent_id": agent_id}


@router.delete("/{agent_id}/isolate", status_code=status.HTTP_202_ACCEPTED)
async def lift_isolation(
    agent_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role=Depends(require_permission(Permission.CONTAINMENT_APPLY)),
) -> dict:
    """Queue a lift-isolation command."""
    await push_command(agent_id, {"type": "lift_isolation"})
    logger.info("Lift-isolation command queued for agent %s", agent_id)
    return {"status": "queued", "agent_id": agent_id}
