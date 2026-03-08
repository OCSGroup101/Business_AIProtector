# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""SQLAlchemy model for staged agent update deployments."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)

    # Semantic version e.g. "1.2.3"
    version: Mapped[str] = mapped_column(String(32), nullable=False)

    # stable | beta | canary
    channel: Mapped[str] = mapped_column(String(16), nullable=False, default="stable")

    # 0-100 rollout percentage
    rollout_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # windows | linux | macos | None (all platforms)
    target_os: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # HTTPS URL to the agent binary
    binary_url: Mapped[str] = mapped_column(String(2048), nullable=False)

    # SHA-256 hex digest of the binary
    binary_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # URL to the .minisig Ed25519 signature file
    signature_url: Mapped[str] = mapped_column(String(2048), nullable=False)

    # pending | rolling_out | paused | completed | rolled_back
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")

    # Error rate threshold that triggers auto-rollback (0.0–1.0)
    auto_rollback_threshold: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.05
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
