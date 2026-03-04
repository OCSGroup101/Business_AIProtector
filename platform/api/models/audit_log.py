"""Immutable audit log — append-only, no update/delete permitted."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    # Who performed the action
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # What was done
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Context
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="SUCCESS")
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True
    )
