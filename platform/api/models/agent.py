"""Agent model — per-tenant schema."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class Agent(Base):
    __tablename__ = "agents"
    # No schema set — uses tenant schema via search_path

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    os_platform: Mapped[str] = mapped_column(String(32), nullable=False)  # windows|macos|linux
    os_version: Mapped[str] = mapped_column(String(64), nullable=False)
    os_arch: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)

    # State: ENROLLING | ACTIVE | ISOLATED | UPDATING
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ENROLLING")

    # Policy
    policy_id: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # mTLS certificate serial
    cert_serial: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cert_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Health / last seen
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_heartbeat_metrics: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enrolled_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    tags: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
