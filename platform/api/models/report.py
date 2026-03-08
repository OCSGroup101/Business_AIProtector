# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""SQLAlchemy model for generated reports."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    # incident_summary | executive
    type: Mapped[str] = mapped_column(String(32), nullable=False)

    # pending | generating | ready | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")

    # MinIO object key for the generated PDF/HTML
    storage_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
