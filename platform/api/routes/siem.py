# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""SIEM connector management endpoints."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from ..audit_service import emit as audit_emit
from ..database import get_tenant_session
from ..middleware.rbac import Permission, Role, require_permission
from ..models.incident import Incident
from ..models.siem_connector import SiemConnectorModel

logger = logging.getLogger(__name__)

router = APIRouter()

# 256-bit AES key for SIEM config encryption; loaded from environment
_AES_KEY_HEX = os.environ.get("SIEM_ENCRYPT_KEY", "0" * 64)
try:
    _AES_KEY = bytes.fromhex(_AES_KEY_HEX[:64])
except ValueError:
    _AES_KEY = b"\x00" * 32


# ─── Encryption helpers ───────────────────────────────────────────────────────


def _encrypt_config(config: dict[str, Any]) -> str:
    """Encrypt a config dict with AES-256-GCM. Returns 'hex_nonce:hex_ciphertext'."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(_AES_KEY)
    ct = aesgcm.encrypt(nonce, json.dumps(config).encode(), None)
    return f"{nonce.hex()}:{ct.hex()}"


def _decrypt_config(encrypted: str) -> dict[str, Any]:
    """Decrypt an AES-256-GCM encrypted config string. Returns parsed dict."""
    nonce_hex, ct_hex = encrypted.split(":", 1)
    aesgcm = AESGCM(_AES_KEY)
    plaintext = aesgcm.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)
    return json.loads(plaintext.decode())  # type: ignore[no-any-return]


# ─── Schemas ─────────────────────────────────────────────────────────────────


class SiemConnectorCreate(BaseModel):
    name: str
    connector_type: str  # splunk | elasticsearch | sentinel
    config: dict[str, Any]  # connector-specific config (will be encrypted at rest)
    enabled: bool = True


class SiemConnectorResponse(BaseModel):
    id: str
    name: str
    connector_type: str
    enabled: bool
    last_test_at: Optional[datetime] = None
    last_test_ok: Optional[bool] = None
    created_at: datetime


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _build_connector(row: SiemConnectorModel) -> SiemConnectorResponse:
    return SiemConnectorResponse(
        id=row.id,
        name=row.name,
        connector_type=row.connector_type,
        enabled=row.enabled,
        last_test_at=row.last_test_at,
        last_test_ok=row.last_test_ok,
        created_at=row.created_at,
    )


async def _instantiate_connector(row: SiemConnectorModel):  # type: ignore[no-untyped-def]
    """Decrypt config and instantiate the appropriate connector class."""
    config = _decrypt_config(row.config_encrypted)
    if row.connector_type == "splunk":
        from ..siem.splunk import SplunkHecConnector

        return SplunkHecConnector(**config)
    elif row.connector_type == "elasticsearch":
        from ..siem.elasticsearch import ElasticsearchConnector

        return ElasticsearchConnector(**config)
    elif row.connector_type == "sentinel":
        from ..siem.sentinel import SentinelConnector

        return SentinelConnector(**config)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown connector_type: {row.connector_type}",
        )


# ─── Routes ──────────────────────────────────────────────────────────────────


@router.post(
    "/connectors",
    response_model=SiemConnectorResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    body: SiemConnectorCreate = Body(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INTEL_WRITE)),
) -> SiemConnectorResponse:
    """Register a new SIEM connector (TENANT_ADMIN or SECURITY_ADMIN)."""
    valid_types = {"splunk", "elasticsearch", "sentinel"}
    if body.connector_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"connector_type must be one of: {sorted(valid_types)}",
        )

    tenant_id = (
        getattr(http_request.state, "tenant_id", None) if http_request else None
    ) or "dev_tenant"

    row = SiemConnectorModel(
        id=f"siem_{ULID()}",
        tenant_id=tenant_id,
        name=body.name,
        connector_type=body.connector_type,
        config_encrypted=_encrypt_config(body.config),
        enabled=body.enabled,
        created_at=datetime.now(tz=timezone.utc),
        updated_at=datetime.now(tz=timezone.utc),
    )
    db.add(row)
    await db.flush()

    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="siem_connector.created",
        resource_type="siem_connector",
        resource_id=row.id,
        outcome="SUCCESS",
        details={"name": row.name, "connector_type": row.connector_type},
        tenant_id=tenant_id,
    )

    return _build_connector(row)


@router.get("/connectors", response_model=list[SiemConnectorResponse])
async def list_connectors(
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INTEL_READ)),
) -> list[SiemConnectorResponse]:
    """List all SIEM connectors for the tenant."""
    result = await db.execute(select(SiemConnectorModel))
    return [_build_connector(r) for r in result.scalars()]


@router.delete("/connectors/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: str = Path(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INTEL_WRITE)),
) -> None:
    """Delete a SIEM connector registration."""
    result = await db.execute(
        select(SiemConnectorModel).where(SiemConnectorModel.id == connector_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found"
        )

    tenant_id = (
        getattr(http_request.state, "tenant_id", None) if http_request else "unknown"
    )
    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )

    await db.delete(row)
    await db.flush()

    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="siem_connector.deleted",
        resource_type="siem_connector",
        resource_id=connector_id,
        outcome="SUCCESS",
        tenant_id=tenant_id,
    )


@router.post("/connectors/{connector_id}/test", response_model=dict)
async def test_connector(
    connector_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INTEL_WRITE)),
) -> dict:
    """Test connectivity for a registered SIEM connector."""
    result = await db.execute(
        select(SiemConnectorModel).where(SiemConnectorModel.id == connector_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found"
        )

    connector = await _instantiate_connector(row)
    ok = await connector.test_connection()

    row.last_test_at = datetime.now(tz=timezone.utc)
    row.last_test_ok = ok
    row.updated_at = datetime.now(tz=timezone.utc)
    await db.flush()

    return {"connector_id": connector_id, "ok": ok}


@router.post(
    "/connectors/{connector_id}/forward-incident/{incident_id}",
    response_model=dict,
)
async def forward_incident(
    connector_id: str = Path(...),
    incident_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INCIDENTS_READ)),
) -> dict:
    """Manually forward a specific incident to a SIEM connector."""
    conn_result = await db.execute(
        select(SiemConnectorModel).where(SiemConnectorModel.id == connector_id)
    )
    row = conn_result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found"
        )

    inc_result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = inc_result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found"
        )

    incident_dict: dict[str, Any] = {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "rule_id": incident.rule_id,
        "agent_id": incident.agent_id,
        "tenant_id": incident.tenant_id,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
    }

    connector = await _instantiate_connector(row)
    ok = await connector.send_incident(incident_dict)

    return {"connector_id": connector_id, "incident_id": incident_id, "forwarded": ok}
