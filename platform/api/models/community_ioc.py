# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Community IOC submission model — tenant-submitted IOCs for community sharing."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class CommunityIoc(Base):
    __tablename__ = "community_iocs"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    # Submitting tenant (stripped when exporting to other tenants)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    submitted_by: Mapped[str] = mapped_column(String(256), nullable=False)

    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)

    # pending | verified | unverified
    verification_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
