# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Custom TAXII/STIX feed registration model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class CustomFeed(Base):
    __tablename__ = "custom_feeds"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    taxii_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    collection_id: Mapped[str] = mapped_column(String(256), nullable=False)

    # AES-256-GCM encrypted API key; hex-encoded ciphertext:nonce
    api_key_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ISO8601 timestamp cursor for incremental polling
    last_cursor: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
