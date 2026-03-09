# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Custom TAXII/STIX feed registration endpoints."""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ulid import ULID

from ..database import get_tenant_session
from ..models.custom_feed import CustomFeed
from ..middleware.rbac import Permission, require_permission, Role
from ..audit_service import emit as audit_emit

logger = logging.getLogger(__name__)

router = APIRouter()

# 256-bit AES key for API key encryption; loaded from environment
_AES_KEY_HEX = os.environ.get("FEED_ENCRYPT_KEY", "0" * 64)
try:
    _AES_KEY = bytes.fromhex(_AES_KEY_HEX[:64])
except ValueError:
    _AES_KEY = b"\x00" * 32


# ─── Schemas ─────────────────────────────────────────────────────────────────


class CustomFeedCreate(BaseModel):
    name: str
    taxii_url: str
    collection_id: str
    api_key: Optional[str] = None


class CustomFeedResponse(BaseModel):
    id: str
    name: str
    taxii_url: str
    collection_id: str
    enabled: bool
    last_cursor: Optional[str] = None
    created_at: datetime


class CustomFeedUpdate(BaseModel):
    enabled: Optional[bool] = None
    api_key: Optional[str] = None


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _encrypt_api_key(plaintext: str) -> str:
    """Encrypt an API key with AES-256-GCM.  Returns 'hex_nonce:hex_ciphertext'."""
    import os as _os

    aesgcm = AESGCM(_AES_KEY)
    nonce = _os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return f"{nonce.hex()}:{ct.hex()}"


def _decrypt_api_key(encrypted: str) -> str:
    """Decrypt an AES-256-GCM encrypted API key."""
    nonce_hex, ct_hex = encrypted.split(":", 1)
    aesgcm = AESGCM(_AES_KEY)
    return aesgcm.decrypt(
        bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None
    ).decode()


# ─── Routes ──────────────────────────────────────────────────────────────────


@router.get("", response_model=list[CustomFeedResponse])
async def list_custom_feeds(
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INTEL_READ)),
) -> list[CustomFeedResponse]:
    """List all custom TAXII feeds for the tenant."""
    result = await db.execute(select(CustomFeed))
    return [
        CustomFeedResponse(
            id=f.id,
            name=f.name,
            taxii_url=f.taxii_url,
            collection_id=f.collection_id,
            enabled=f.enabled,
            last_cursor=f.last_cursor,
            created_at=f.created_at,
        )
        for f in result.scalars()
    ]


@router.post("", response_model=CustomFeedResponse, status_code=status.HTTP_201_CREATED)
async def create_custom_feed(
    body: CustomFeedCreate = Body(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INTEL_WRITE)),
) -> CustomFeedResponse:
    """Register a new custom TAXII/STIX feed."""
    tenant_id = (
        getattr(http_request.state, "tenant_id", None) if http_request else None
    ) or "dev_tenant"

    encrypted_key = _encrypt_api_key(body.api_key) if body.api_key else None

    feed = CustomFeed(
        id=f"feed_{ULID()}",
        tenant_id=tenant_id,
        name=body.name,
        taxii_url=body.taxii_url,
        collection_id=body.collection_id,
        api_key_encrypted=encrypted_key,
        enabled=True,
    )
    db.add(feed)
    await db.flush()

    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="intel_feed.created",
        resource_type="custom_feed",
        resource_id=feed.id,
        outcome="SUCCESS",
        details={"name": feed.name, "taxii_url": feed.taxii_url},
        tenant_id=tenant_id,
    )

    return CustomFeedResponse(
        id=feed.id,
        name=feed.name,
        taxii_url=feed.taxii_url,
        collection_id=feed.collection_id,
        enabled=feed.enabled,
        last_cursor=feed.last_cursor,
        created_at=feed.created_at,
    )


@router.delete("/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_custom_feed(
    feed_id: str = Path(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.INTEL_WRITE)),
) -> None:
    """Delete a custom TAXII feed registration."""
    result = await db.execute(select(CustomFeed).where(CustomFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if feed is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found"
        )

    tenant_id = (
        getattr(http_request.state, "tenant_id", None) if http_request else "unknown"
    )
    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )

    await db.delete(feed)
    await db.flush()

    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="intel_feed.deleted",
        resource_type="custom_feed",
        resource_id=feed_id,
        outcome="SUCCESS",
        tenant_id=tenant_id,
    )


@router.patch("/{feed_id}", response_model=CustomFeedResponse)
async def update_custom_feed(
    feed_id: str = Path(...),
    body: CustomFeedUpdate = Body(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.INTEL_WRITE)),
) -> CustomFeedResponse:
    """Enable/disable a custom feed or rotate its API key."""
    result = await db.execute(select(CustomFeed).where(CustomFeed.id == feed_id))
    feed = result.scalar_one_or_none()
    if feed is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found"
        )

    if body.enabled is not None:
        feed.enabled = body.enabled
    if body.api_key is not None:
        feed.api_key_encrypted = _encrypt_api_key(body.api_key)
    feed.updated_at = datetime.now(tz=timezone.utc)
    await db.flush()

    return CustomFeedResponse(
        id=feed.id,
        name=feed.name,
        taxii_url=feed.taxii_url,
        collection_id=feed.collection_id,
        enabled=feed.enabled,
        last_cursor=feed.last_cursor,
        created_at=feed.created_at,
    )
