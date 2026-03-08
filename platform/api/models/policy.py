"""Policy model — per-tenant schema."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # TOML policy content
    content_toml: Mapped[str] = mapped_column(Text, nullable=False)

    # Ed25519 minisign signature of the TOML content
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Per-rule enabled/disabled overrides: { "<rule_id>": { "enabled": bool } }
    # Rules absent from this map inherit the enabled flag from content_toml.
    rule_overrides: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # How many agents are on this policy
    agent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
