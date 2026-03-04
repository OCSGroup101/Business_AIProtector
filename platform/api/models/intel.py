"""IOC entry model — per-tenant schema."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class IocEntry(Base):
    __tablename__ = "ioc_entries"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    # IOC data
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)   # file_hash|ip_address|domain|url
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    value_lower: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    # Metadata
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.7)
    sources: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Lifecycle
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
