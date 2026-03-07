# Copyright 2024 Omni Cyber Solutions LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Agent enrollment endpoint — one-time token → mTLS client certificate."""

import hashlib
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from .. import pki
from ..database import AsyncSessionLocal, get_db
from ..models.agent import Agent
from ..models.enrollment_token import EnrollmentToken
from ..models.policy import Policy

logger = logging.getLogger(__name__)

router = APIRouter()

# ─── Request / Response models ────────────────────────────────────────────────


class EnrollmentRequest(BaseModel):
    """Sent by the agent during --enroll."""

    token: str
    hostname: str
    os_platform: str
    os_version: str
    os_arch: str
    agent_version: str
    csr_pem: str


class EnrollmentResponse(BaseModel):
    """Returned to the agent on successful enrollment."""

    agent_id: str
    tenant_id: str
    client_cert_pem: str
    ca_cert_pem: str
    # Seconds before the cert expires — agent should auto-renew when this drops below 86400
    cert_valid_seconds: int
    policy: dict


# ─── Endpoint ─────────────────────────────────────────────────────────────────


@router.post(
    "/enroll",
    response_model=EnrollmentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def enroll_agent(
    request: EnrollmentRequest,
    db: AsyncSession = Depends(get_db),
) -> EnrollmentResponse:
    """
    Enroll a new agent using a one-time token.

    Flow:
    1. Hash the incoming token (SHA-256) and look up EnrollmentToken in public schema.
    2. Validate: active, not expired, use_count < max_uses.
    3. Sign the agent CSR with the platform CA → 72-hour mTLS client cert.
    4. Create Agent record in the tenant's schema.
    5. Mark token used (increment use_count, record agent_id).
    6. Return cert + CA cert + initial policy bundle.
    """
    # ── 1. Validate token ─────────────────────────────────────────────────────
    if not request.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token is required",
        )

    token_hash = hashlib.sha256(request.token.encode()).hexdigest()

    result = await db.execute(
        select(EnrollmentToken)
        .where(EnrollmentToken.token_hash == token_hash)
        .where(EnrollmentToken.is_active.is_(True))
        .with_for_update()  # prevent concurrent use of the same token
    )
    token_record = result.scalar_one_or_none()

    if token_record is None:
        # Don't distinguish "invalid" vs "expired" to avoid oracle attacks
        logger.warning(
            "Enrollment attempt with unknown/inactive token hash=%s... (host=%s)",
            token_hash[:8],
            request.hostname,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired enrollment token",
        )

    now = datetime.now(timezone.utc)

    if token_record.expires_at.tzinfo is None:
        # Normalise naive datetime from DB
        expires_at = token_record.expires_at.replace(tzinfo=timezone.utc)
    else:
        expires_at = token_record.expires_at

    if now > expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enrollment token has expired",
        )

    if token_record.use_count >= token_record.max_uses:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enrollment token has already been used",
        )

    tenant_id = token_record.tenant_id

    # ── 2. Issue mTLS client certificate ─────────────────────────────────────
    agent_id = f"agt_{ULID()}"

    try:
        client_cert_pem, ca_cert_pem, cert_serial, cert_expires_at = pki.sign_agent_csr(
            csr_pem=request.csr_pem,
            agent_id=agent_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CSR validation failed: {exc}",
        )

    cert_valid_seconds = int((cert_expires_at - now).total_seconds())

    # ── 3. Create Agent record in tenant schema ───────────────────────────────
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    async with AsyncSessionLocal() as tenant_session:
        try:
            await tenant_session.execute(
                text(f"SET LOCAL search_path TO {schema}, public")
            )
            await tenant_session.execute(
                text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
            )

            agent = Agent(
                id=agent_id,
                tenant_id=tenant_id,
                hostname=request.hostname,
                os_platform=request.os_platform,
                os_version=request.os_version,
                os_arch=request.os_arch,
                agent_version=request.agent_version,
                state="ACTIVE",
                cert_serial=cert_serial,
                cert_expires_at=cert_expires_at,
                enrolled_at=now,
            )
            tenant_session.add(agent)
            await tenant_session.commit()
        except Exception:
            await tenant_session.rollback()
            raise

    # ── 4. Mark token used ────────────────────────────────────────────────────
    token_record.use_count += 1
    token_record.used_at = now
    token_record.used_by_agent_id = agent_id
    if token_record.use_count >= token_record.max_uses:
        token_record.is_active = False

    # db session commits via get_db dependency

    logger.info(
        "Agent enrolled: agent_id=%s tenant=%s host=%s os=%s/%s",
        agent_id,
        tenant_id,
        request.hostname,
        request.os_platform,
        request.os_arch,
    )

    # ── 5. Fetch default policy for this tenant ───────────────────────────────
    policy_bundle: dict = {"version": 0, "content_toml": ""}
    async with AsyncSessionLocal() as policy_session:
        await policy_session.execute(text(f"SET LOCAL search_path TO {schema}, public"))
        pol_result = await policy_session.execute(
            select(Policy)
            .where(Policy.is_default.is_(True), Policy.is_active.is_(True))
            .order_by(Policy.version.desc())
            .limit(1)
        )
        default_policy = pol_result.scalar_one_or_none()
        if default_policy:
            policy_bundle = {
                "version": default_policy.version,
                "content_toml": default_policy.content_toml,
            }

    return EnrollmentResponse(
        agent_id=agent_id,
        tenant_id=tenant_id,
        client_cert_pem=client_cert_pem,
        ca_cert_pem=ca_cert_pem,
        cert_valid_seconds=cert_valid_seconds,
        policy=policy_bundle,
    )
