"""Incident and IncidentEvent models — per-tenant schema."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, JSON, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)

    # Detection info
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # CRITICAL|HIGH|MEDIUM|LOW|INFO
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Lifecycle: OPEN | INVESTIGATING | CONTAINED | RESOLVED | FALSE_POSITIVE
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN")
    assigned_to: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Summary (Claude-generated or template)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Containment
    containment_status: Mapped[Optional[str]] = mapped_column(String(24), nullable=True)
    containment_actions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )

    events: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="incident", cascade="all, delete-orphan"
    )


class IncidentEvent(Base):
    """Individual telemetry events linked to an incident (timeline)."""
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(String(30), nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="events")
