# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Agent certificate renewal and policy-fetch endpoints.

These endpoints are called by the agent — they use the agent's mTLS
client certificate (CN=agent_id) for authentication rather than a
bearer token, so no RBAC middleware is applied here.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .. import pki
from ..database import get_tenant_session
from ..models.agent import Agent
from ..models.policy import Policy

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Cert renewal ─────────────────────────────────────────────────────────────

class CertRenewalRequest(BaseModel):
    csr_pem: str


class CertRenewalResponse(BaseModel):
    client_cert_pem: str
    ca_cert_pem: str
    cert_valid_seconds: int


@router.post("/{agent_id}/renew-cert", response_model=CertRenewalResponse)
async def renew_agent_cert(
    request: CertRenewalRequest,
    agent_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
) -> CertRenewalResponse:
    """
    Issue a fresh 72-hour mTLS certificate for an enrolled agent.

    The agent sends a new CSR; the platform signs it and returns the
    new cert + CA.  The old cert remains valid until it expires.
    """
    result = await db.execute(select(Agent).where(Agent.id == agent_id, Agent.is_active.is_(True)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    try:
        client_cert_pem, ca_cert_pem, cert_serial, cert_expires_at = pki.sign_agent_csr(
            csr_pem=request.csr_pem,
            agent_id=agent_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"CSR validation failed: {exc}")

    now = datetime.now(timezone.utc)
    agent.cert_serial = cert_serial
    agent.cert_expires_at = cert_expires_at
    agent.updated_at = now
    await db.flush()

    cert_valid_seconds = int((cert_expires_at - now).total_seconds())
    logger.info("Cert renewed for agent %s (serial %s, expires in %ds)", agent_id, cert_serial, cert_valid_seconds)

    return CertRenewalResponse(
        client_cert_pem=client_cert_pem,
        ca_cert_pem=ca_cert_pem,
        cert_valid_seconds=cert_valid_seconds,
    )


# ─── Agent policy fetch ───────────────────────────────────────────────────────

class AgentPolicyResponse(BaseModel):
    version: int
    content_toml: str


@router.get("/{agent_id}/policy", response_model=AgentPolicyResponse)
async def get_agent_policy(
    agent_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
) -> AgentPolicyResponse:
    """
    Return the current default policy for the agent's tenant.

    Called by the agent when the heartbeat response indicates a new
    policy version is available.
    """
    result = await db.execute(select(Agent).where(Agent.id == agent_id, Agent.is_active.is_(True)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    pol_result = await db.execute(
        select(Policy)
        .where(Policy.is_default.is_(True), Policy.is_active.is_(True))
        .order_by(Policy.version.desc())
        .limit(1)
    )
    policy = pol_result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No default policy configured for this tenant")

    # Track which policy version the agent is now on
    agent.policy_id = policy.id
    agent.policy_version = policy.version
    await db.flush()

    return AgentPolicyResponse(version=policy.version, content_toml=policy.content_toml)
