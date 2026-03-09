# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Staged agent update deployment endpoints."""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from ..audit_service import emit as audit_emit
from ..database import get_tenant_session
from ..middleware.rbac import Permission, Role, require_permission
from ..models.agent import Agent
from ..models.deployment import Deployment

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Schemas ─────────────────────────────────────────────────────────────────


class DeploymentCreate(BaseModel):
    version: str
    channel: str = "stable"
    rollout_pct: int = Field(default=0, ge=0, le=100)
    target_os: Optional[str] = None  # windows | linux | macos | None (all)
    binary_url: str
    binary_sha256: str
    signature_url: str
    auto_rollback_threshold: float = Field(default=0.05, ge=0.0, le=1.0)


class DeploymentResponse(BaseModel):
    id: str
    version: str
    channel: str
    rollout_pct: int
    target_os: Optional[str]
    binary_url: str
    binary_sha256: str
    signature_url: str
    status: str
    auto_rollback_threshold: float
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class DeploymentStatusResponse(DeploymentResponse):
    agent_count_enrolled: int = 0
    agent_count_updated: int = 0


class CurrentDeploymentResponse(BaseModel):
    version: str
    binary_url: str
    binary_sha256: str
    signature_url: str
    channel: str


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _to_response(d: Deployment) -> DeploymentResponse:
    return DeploymentResponse(
        id=d.id,
        version=d.version,
        channel=d.channel,
        rollout_pct=d.rollout_pct,
        target_os=d.target_os,
        binary_url=d.binary_url,
        binary_sha256=d.binary_sha256,
        signature_url=d.signature_url,
        status=d.status,
        auto_rollback_threshold=d.auto_rollback_threshold,
        created_at=d.created_at,
        started_at=d.started_at,
        completed_at=d.completed_at,
    )


# ─── Routes ──────────────────────────────────────────────────────────────────


@router.post(
    "/",
    response_model=DeploymentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_deployment(
    body: DeploymentCreate = Body(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.AGENTS_WRITE)),
) -> DeploymentResponse:
    """Create a new staged deployment (SECURITY_ADMIN+)."""
    valid_os = {None, "windows", "linux", "macos"}
    if body.target_os not in valid_os:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_os must be windows, linux, macos, or null",
        )
    valid_channels = {"stable", "beta", "canary"}
    if body.channel not in valid_channels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"channel must be one of: {sorted(valid_channels)}",
        )

    deployment = Deployment(
        id=f"dep_{ULID()}",
        version=body.version,
        channel=body.channel,
        rollout_pct=body.rollout_pct,
        target_os=body.target_os,
        binary_url=body.binary_url,
        binary_sha256=body.binary_sha256,
        signature_url=body.signature_url,
        status="pending",
        auto_rollback_threshold=body.auto_rollback_threshold,
        created_at=datetime.now(tz=timezone.utc),
    )
    db.add(deployment)
    await db.flush()

    tenant_id = (
        str(getattr(http_request.state, "tenant_id", "dev_tenant") or "dev_tenant")
        if http_request
        else "dev_tenant"
    )
    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="deployment.created",
        resource_type="deployment",
        resource_id=deployment.id,
        outcome="SUCCESS",
        details={"version": deployment.version, "channel": deployment.channel},
        tenant_id=tenant_id,
    )

    return _to_response(deployment)


@router.get("/current", response_model=Optional[CurrentDeploymentResponse])
async def get_current_deployment(
    os_platform: Optional[str] = None,
    channel: str = "stable",
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.AGENTS_READ)),
) -> Optional[CurrentDeploymentResponse]:
    """
    Return the current active deployment for the given OS/channel.
    Used by agent heartbeat to check for pending updates.
    """
    query = (
        select(Deployment)
        .where(
            Deployment.status == "rolling_out",
            Deployment.channel == channel,
        )
        .order_by(Deployment.created_at.desc())
        .limit(1)
    )
    if os_platform:
        query = query.where(
            (Deployment.target_os == os_platform) | (Deployment.target_os.is_(None))
        )
    result = await db.execute(query)
    dep = result.scalar_one_or_none()
    if dep is None:
        return None
    return CurrentDeploymentResponse(
        version=dep.version,
        binary_url=dep.binary_url,
        binary_sha256=dep.binary_sha256,
        signature_url=dep.signature_url,
        channel=dep.channel,
    )


@router.get("/", response_model=list[DeploymentResponse])
async def list_deployments(
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.AGENTS_READ)),
) -> list[DeploymentResponse]:
    """List all deployments."""
    result = await db.execute(select(Deployment).order_by(Deployment.created_at.desc()))
    return [_to_response(d) for d in result.scalars()]


@router.get("/{deployment_id}", response_model=DeploymentStatusResponse)
async def get_deployment(
    deployment_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.AGENTS_READ)),
) -> DeploymentStatusResponse:
    """Get deployment status including enrolled vs updated agent counts."""
    result = await db.execute(select(Deployment).where(Deployment.id == deployment_id))
    dep = result.scalar_one_or_none()
    if dep is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found"
        )

    # Count enrolled agents matching the target OS filter
    agent_query = select(func.count(Agent.id)).where(Agent.is_active.is_(True))
    if dep.target_os:
        agent_query = agent_query.where(Agent.os_platform == dep.target_os)
    enrolled_result = await db.execute(agent_query)
    enrolled_count: int = enrolled_result.scalar_one() or 0

    # Count agents already on this version
    updated_query = select(func.count(Agent.id)).where(
        Agent.agent_version == dep.version,
        Agent.is_active.is_(True),
    )
    if dep.target_os:
        updated_query = updated_query.where(Agent.os_platform == dep.target_os)
    updated_result = await db.execute(updated_query)
    updated_count: int = updated_result.scalar_one() or 0

    return DeploymentStatusResponse(
        **_to_response(dep).model_dump(),
        agent_count_enrolled=enrolled_count,
        agent_count_updated=updated_count,
    )


@router.post("/{deployment_id}/pause", response_model=DeploymentResponse)
async def pause_deployment(
    deployment_id: str = Path(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.AGENTS_WRITE)),
) -> DeploymentResponse:
    """Pause a rolling-out deployment."""
    result = await db.execute(select(Deployment).where(Deployment.id == deployment_id))
    dep = result.scalar_one_or_none()
    if dep is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found"
        )
    if dep.status != "rolling_out":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot pause deployment in status: {dep.status}",
        )
    dep.status = "paused"
    await db.flush()

    tenant_id = (
        str(getattr(http_request.state, "tenant_id", "dev_tenant") or "dev_tenant")
        if http_request
        else "dev_tenant"
    )
    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="deployment.paused",
        resource_type="deployment",
        resource_id=deployment_id,
        outcome="SUCCESS",
        tenant_id=tenant_id,
    )
    return _to_response(dep)


@router.post("/{deployment_id}/resume", response_model=DeploymentResponse)
async def resume_deployment(
    deployment_id: str = Path(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.AGENTS_WRITE)),
) -> DeploymentResponse:
    """Resume a paused deployment."""
    result = await db.execute(select(Deployment).where(Deployment.id == deployment_id))
    dep = result.scalar_one_or_none()
    if dep is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found"
        )
    if dep.status not in ("paused", "pending"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot resume deployment in status: {dep.status}",
        )
    dep.status = "rolling_out"
    if dep.started_at is None:
        dep.started_at = datetime.now(tz=timezone.utc)
    await db.flush()

    tenant_id = (
        str(getattr(http_request.state, "tenant_id", "dev_tenant") or "dev_tenant")
        if http_request
        else "dev_tenant"
    )
    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="deployment.resumed",
        resource_type="deployment",
        resource_id=deployment_id,
        outcome="SUCCESS",
        tenant_id=tenant_id,
    )
    return _to_response(dep)


@router.post("/{deployment_id}/rollback", response_model=DeploymentResponse)
async def rollback_deployment(
    deployment_id: str = Path(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.AGENTS_WRITE)),
) -> DeploymentResponse:
    """
    Trigger a rollback.  Sets status=rolled_back.
    Agents receive a rollback command via the next heartbeat response.
    """
    result = await db.execute(select(Deployment).where(Deployment.id == deployment_id))
    dep = result.scalar_one_or_none()
    if dep is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found"
        )
    if dep.status in ("completed", "rolled_back"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot rollback deployment in status: {dep.status}",
        )

    dep.status = "rolled_back"
    dep.completed_at = datetime.now(tz=timezone.utc)
    await db.flush()

    tenant_id = (
        str(getattr(http_request.state, "tenant_id", "dev_tenant") or "dev_tenant")
        if http_request
        else "dev_tenant"
    )
    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="deployment.rolled_back",
        resource_type="deployment",
        resource_id=deployment_id,
        outcome="SUCCESS",
        tenant_id=tenant_id,
    )
    return _to_response(dep)
