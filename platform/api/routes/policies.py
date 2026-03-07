"""Policy management endpoints."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ulid import ULID

from ..database import get_db
from ..models.policy import Policy
from ..middleware.rbac import Permission, require_permission

logger = logging.getLogger(__name__)

router = APIRouter()


class PolicySummary(BaseModel):
    id: str
    name: str
    version: int
    is_default: bool
    agent_count: int
    created_at: datetime


class CreatePolicyRequest(BaseModel):
    name: str
    description: Optional[str] = None
    content_toml: str
    is_default: bool = False


@router.get("", response_model=list[PolicySummary])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    _role=Depends(require_permission(Permission.POLICIES_READ)),
) -> list[PolicySummary]:
    result = await db.execute(select(Policy).where(Policy.is_active.is_(True)))
    return [
        PolicySummary(
            id=p.id,
            name=p.name,
            version=p.version,
            is_default=p.is_default,
            agent_count=p.agent_count,
            created_at=p.created_at,
        )
        for p in result.scalars()
    ]


@router.post("", response_model=PolicySummary, status_code=status.HTTP_201_CREATED)
async def create_policy(
    request: CreatePolicyRequest,
    db: AsyncSession = Depends(get_db),
    _role=Depends(require_permission(Permission.POLICIES_WRITE)),
) -> PolicySummary:
    """Create a new policy. TOML content will be validated and signed server-side."""
    # Phase 1: Validate TOML schema, sign with platform key
    policy = Policy(
        id=f"pol_{ULID()}",
        tenant_id="dev_tenant",  # Phase 1: from request context
        name=request.name,
        description=request.description,
        content_toml=request.content_toml,
        version=1,
        is_default=request.is_default,
    )
    db.add(policy)
    await db.flush()
    logger.info("Policy created: %s (%s)", policy.id, policy.name)
    return PolicySummary(
        id=policy.id,
        name=policy.name,
        version=policy.version,
        is_default=policy.is_default,
        agent_count=0,
        created_at=policy.created_at,
    )
