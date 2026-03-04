# Copyright 2024 Omni Cyber Solutions LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Enrollment token model — public schema, created by tenant admins before agent deployment."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class EnrollmentToken(Base):
    """
    One-time (or limited-use) token that authorizes an agent to enroll.

    Lives in the public schema. The token value itself is never stored —
    only its SHA-256 hash. The plaintext token is returned once at creation
    and must be delivered to the agent out-of-band.
    """

    __tablename__ = "enrollment_tokens"
    __table_args__ = {"schema": "public"}

    id: Mapped[str] = mapped_column(String(30), primary_key=True)

    # Which tenant this token grants enrollment into
    tenant_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    # SHA-256 hex digest of the plaintext token (never store plaintext)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Human-readable label for audit purposes
    label: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Who created this token (operator user ID)
    created_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )

    # Token expires at this time; enrollment after expiry is rejected
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Set when the token is used; NULL = not yet used
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Agent that consumed this token
    used_by_agent_id: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    # Maximum number of times this token can be used (default: 1 for single-agent tokens)
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Incremented on each successful use
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Set to False when use_count reaches max_uses or token is manually revoked
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
