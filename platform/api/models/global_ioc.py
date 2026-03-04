# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""GlobalIocEntry — threat intel IOCs shared across all tenants (public schema)."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class GlobalIocEntry(Base):
    """
    IOC records fetched from global threat feeds (MalwareBazaar, URLHaus, etc.).
    Stored in the public schema — accessible to all tenants via the ioc-bundle endpoint.
    Key: (ioc_type, value_lower) — unique constraint prevents duplicates.
    """

    __tablename__ = "global_ioc_entries"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value_lower", name="uq_global_ioc_type_value"),
        {"schema": "public"},
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)

    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)  # file_hash|ip_address|domain|url
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    value_lower: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    score: Mapped[float] = mapped_column(Float, nullable=False)
    sources: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    feed_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
