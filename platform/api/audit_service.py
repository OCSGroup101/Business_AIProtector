# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Audit log emission service.

emit() is the single write path for all audit log entries.  It wraps the
INSERT in a try/except so that audit failures NEVER block the primary
operation — security visibility should not degrade UX.

Usage:
    from .audit_service import emit
    await emit(
        db=db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=request.client.host,
        action="incident.status_changed",
        resource_type="incident",
        resource_id=incident_id,
        outcome="SUCCESS",
    )

PostgreSQL hardening note: production deployments should add an RLS policy
that blocks UPDATE/DELETE on audit_logs for the openclaw DB user:
    CREATE POLICY audit_immutable ON audit_logs
        AS RESTRICTIVE FOR ALL TO openclaw
        USING (true) WITH CHECK (false);
    -- Then override for INSERT only:
    CREATE POLICY audit_insert ON audit_logs FOR INSERT TO openclaw WITH CHECK (true);
"""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .models.audit_log import AuditLog

logger = logging.getLogger(__name__)


async def emit(
    db: AsyncSession,
    *,
    actor_id: str,
    actor_role: str,
    actor_ip: Optional[str] = None,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    outcome: str = "SUCCESS",
    details: Optional[dict[str, Any]] = None,
    failure_reason: Optional[str] = None,
    tenant_id: str = "system",
) -> None:
    """
    Append an audit log entry.  Never raises — audit failure must not block
    the primary operation.
    """
    try:
        from ulid import ULID

        entry = AuditLog(
            id=f"aud_{ULID()}",
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            actor_ip=actor_ip,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome.upper(),
            details=details,
            failure_reason=failure_reason,
            occurred_at=datetime.now(tz=timezone.utc),
        )
        db.add(entry)
        # flush without committing — the outer request transaction commits
        await db.flush()
    except Exception as exc:  # pragma: no cover
        logger.warning("audit_service.emit failed (non-fatal): %s", exc)
