"""Policy management endpoints."""

import logging
import tomllib
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, status
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


class DetectionRuleResponse(BaseModel):
    id: str
    rule_id: str
    name: str
    enabled: bool
    severity: str
    mitre_techniques: list[str]
    match_type: str


class UpdateRuleRequest(BaseModel):
    enabled: bool


@router.get("", response_model=list[PolicySummary])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    _role=Depends(require_permission(Permission.POLICIES_READ)),
) -> list[PolicySummary]:
    result = await db.execute(select(Policy).where(Policy.is_active == True))
    return [
        PolicySummary(
            id=p.id, name=p.name, version=p.version,
            is_default=p.is_default, agent_count=p.agent_count,
            created_at=p.created_at,
        )
        for p in result.scalars()
    ]


@router.get("/{policy_id}/rules", response_model=list[DetectionRuleResponse])
async def list_policy_rules(
    policy_id: str = Path(...),
    db: AsyncSession = Depends(get_db),
    _role=Depends(require_permission(Permission.POLICIES_READ)),
) -> list[DetectionRuleResponse]:
    """Return detection rules from a policy's TOML, merged with per-rule overrides."""
    result = await db.execute(select(Policy).where(Policy.id == policy_id, Policy.is_active == True))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")

    try:
        parsed: dict[str, Any] = tomllib.loads(policy.content_toml)
    except tomllib.TOMLDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid policy TOML: {exc}")

    rules: list[DetectionRuleResponse] = []
    for raw in parsed.get("rules", []):
        rule_id: str = raw.get("rule_id", "")
        override = policy.rule_overrides.get(rule_id, {})
        enabled = override.get("enabled", raw.get("match", {}).get("enabled", True))
        rules.append(DetectionRuleResponse(
            id=f"{policy_id}:{rule_id}",
            rule_id=rule_id,
            name=raw.get("name", rule_id),
            enabled=enabled,
            severity=raw.get("severity", "medium"),
            mitre_techniques=raw.get("mitre_techniques", []),
            match_type=raw.get("match", {}).get("type", "behavioral"),
        ))
    return rules


@router.patch("/{policy_id}/rules/{rule_id}", response_model=DetectionRuleResponse)
async def update_policy_rule(
    request: UpdateRuleRequest,
    policy_id: str = Path(...),
    rule_id: str = Path(...),
    db: AsyncSession = Depends(get_db),
    _role=Depends(require_permission(Permission.POLICIES_WRITE)),
) -> DetectionRuleResponse:
    """Enable or disable a single detection rule within a policy."""
    result = await db.execute(select(Policy).where(Policy.id == policy_id, Policy.is_active == True))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")

    try:
        parsed: dict[str, Any] = tomllib.loads(policy.content_toml)
    except tomllib.TOMLDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid policy TOML: {exc}")

    raw_rule = next((r for r in parsed.get("rules", []) if r.get("rule_id") == rule_id), None)
    if not raw_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found in policy")

    overrides: dict = dict(policy.rule_overrides)
    overrides[rule_id] = {"enabled": request.enabled}
    policy.rule_overrides = overrides
    policy.updated_at = datetime.utcnow()
    await db.flush()

    logger.info("Rule %s in policy %s set enabled=%s", rule_id, policy_id, request.enabled)
    return DetectionRuleResponse(
        id=f"{policy_id}:{rule_id}",
        rule_id=rule_id,
        name=raw_rule.get("name", rule_id),
        enabled=request.enabled,
        severity=raw_rule.get("severity", "medium"),
        mitre_techniques=raw_rule.get("mitre_techniques", []),
        match_type=raw_rule.get("match", {}).get("type", "behavioral"),
    )


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
        id=policy.id, name=policy.name, version=policy.version,
        is_default=policy.is_default, agent_count=0,
        created_at=policy.created_at,
    )
