# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""SQLAlchemy model for tenant SIEM connector registrations."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class SiemConnectorModel(Base):
    __tablename__ = "siem_connectors"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    # splunk | elasticsearch | sentinel
    connector_type: Mapped[str] = mapped_column(String(32), nullable=False)

    # AES-256-GCM encrypted JSON config; format: hex_nonce:hex_ciphertext
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    last_test_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_test_ok: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
