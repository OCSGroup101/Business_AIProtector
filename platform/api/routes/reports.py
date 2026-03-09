# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Report generation endpoints."""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from ..audit_service import emit as audit_emit
from ..database import get_tenant_session
from ..middleware.rbac import Permission, Role, require_permission
from ..models.incident import Incident
from ..models.report import Report
from ..reports.renderer import render_executive_summary, render_incident_summary

logger = logging.getLogger(__name__)

router = APIRouter()

# Report TTL — pre-signed URLs and stored objects expire after this many seconds
_REPORT_EXPIRY_SECS = int(
    os.environ.get("REPORT_EXPIRY_SECS", str(7 * 86_400))
)  # 7 days


# ─── Schemas ─────────────────────────────────────────────────────────────────


class ReportCreate(BaseModel):
    type: str  # incident_summary | executive
    period_days: int = Field(default=30, ge=1, le=365)


class ReportResponse(BaseModel):
    id: str
    type: str
    status: str
    download_url: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime


# ─── MinIO helper ─────────────────────────────────────────────────────────────


async def _store_report(report_id: str, data: bytes, content_type: str) -> str:
    """
    Upload report bytes to MinIO.  Returns the object key.
    Falls back gracefully if MinIO is not configured.
    """
    bucket = os.environ.get("REPORT_BUCKET", "openclaw-reports")
    minio_url = os.environ.get("MINIO_URL", "")
    minio_access = os.environ.get("MINIO_ACCESS_KEY", "")
    minio_secret = os.environ.get("MINIO_SECRET_KEY", "")

    key = f"reports/{report_id}.pdf"

    if not minio_url:
        logger.warning(
            "MINIO_URL not configured — report %s not stored in object storage",
            report_id,
        )
        return key

    try:
        from minio import Minio  # type: ignore[import-untyped]
        import io as _io

        endpoint = minio_url.replace("http://", "").replace("https://", "").rstrip("/")
        secure = minio_url.startswith("https://")
        client = Minio(
            endpoint, access_key=minio_access, secret_key=minio_secret, secure=secure
        )

        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)

        client.put_object(
            bucket,
            key,
            _io.BytesIO(data),
            length=len(data),
            content_type=content_type,
        )
        logger.info("Report %s stored as %s/%s", report_id, bucket, key)
    except Exception as exc:
        logger.warning("Failed to store report in MinIO: %s", exc)

    return key


def _presigned_url(storage_key: str) -> Optional[str]:
    """Generate a pre-signed MinIO download URL for the report."""
    bucket = os.environ.get("REPORT_BUCKET", "openclaw-reports")
    minio_url = os.environ.get("MINIO_URL", "")
    minio_access = os.environ.get("MINIO_ACCESS_KEY", "")
    minio_secret = os.environ.get("MINIO_SECRET_KEY", "")

    if not minio_url:
        return None

    try:
        from datetime import timedelta as _td
        from minio import Minio  # type: ignore[import-untyped]

        endpoint = minio_url.replace("http://", "").replace("https://", "").rstrip("/")
        secure = minio_url.startswith("https://")
        client = Minio(
            endpoint, access_key=minio_access, secret_key=minio_secret, secure=secure
        )
        url = client.presigned_get_object(
            bucket,
            storage_key,
            expires=_td(seconds=_REPORT_EXPIRY_SECS),
        )
        return url
    except Exception as exc:
        logger.warning("Failed to generate presigned URL: %s", exc)
        return None


# ─── Routes ──────────────────────────────────────────────────────────────────


@router.post("/", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    body: ReportCreate = Body(...),
    http_request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_tenant_session),
    role: Role = Depends(require_permission(Permission.AUDIT_READ)),
) -> ReportResponse:
    """
    Generate a new report.  Queries tenant incidents, renders PDF,
    stores in MinIO, and returns a pre-signed download URL.
    """
    valid_types = {"incident_summary", "executive"}
    if body.type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"type must be one of: {sorted(valid_types)}",
        )

    tenant_id = (
        getattr(http_request.state, "tenant_id", None) if http_request else None
    ) or "dev_tenant"

    # Create report record in pending state
    report_id = f"rpt_{ULID()}"
    expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=_REPORT_EXPIRY_SECS)
    report_row = Report(
        id=report_id,
        tenant_id=tenant_id,
        type=body.type,
        status="generating",
        created_at=datetime.now(tz=timezone.utc),
        expires_at=expires_at,
    )
    db.add(report_row)
    await db.flush()

    # Query incidents for the period
    since = datetime.now(tz=timezone.utc) - timedelta(days=body.period_days)
    inc_result = await db.execute(
        select(Incident)
        .where(Incident.first_seen_at >= since)
        .order_by(Incident.first_seen_at.desc())
        .limit(10000)
    )
    incidents = [
        {
            "id": inc.id,
            "severity": inc.severity,
            "status": inc.status,
            "rule_id": inc.rule_id,
            "rule_name": inc.rule_name,
            "hostname": inc.hostname,
            "agent_id": inc.agent_id,
            "first_seen_at": inc.first_seen_at,
            "last_seen_at": inc.last_seen_at,
        }
        for inc in inc_result.scalars()
    ]

    # Render report
    try:
        if body.type == "incident_summary":
            pdf_bytes = await render_incident_summary(
                incidents, tenant_id=tenant_id, period_days=body.period_days
            )
        else:
            pdf_bytes = await render_executive_summary(
                {"incidents": incidents, "period_days": body.period_days},
                tenant_id=tenant_id,
            )

        # Detect whether we got real PDF or HTML fallback
        content_type = (
            "application/pdf"
            if pdf_bytes[:4] == b"%PDF"
            else "text/html; charset=utf-8"
        )

        storage_key = await _store_report(report_id, pdf_bytes, content_type)
        report_row.status = "ready"
        report_row.storage_key = storage_key

    except Exception as exc:
        logger.error("Report generation failed for %s: %s", report_id, exc)
        report_row.status = "failed"
        await db.flush()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Report generation failed",
        )

    await db.flush()

    download_url = (
        _presigned_url(report_row.storage_key) if report_row.storage_key else None
    )

    actor_ip = (
        http_request.client.host if http_request and http_request.client else None
    )
    await audit_emit(
        db,
        actor_id=role.value,
        actor_role=role.value,
        actor_ip=actor_ip,
        action="report.generated",
        resource_type="report",
        resource_id=report_id,
        outcome="SUCCESS",
        details={"type": body.type, "period_days": body.period_days},
        tenant_id=tenant_id,
    )

    return ReportResponse(
        id=report_id,
        type=report_row.type,
        status=report_row.status,
        download_url=download_url,
        expires_at=expires_at,
        created_at=report_row.created_at,
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: str = Path(...),
    db: AsyncSession = Depends(get_tenant_session),
    _role: Role = Depends(require_permission(Permission.AUDIT_READ)),
) -> ReportResponse:
    """Return report metadata and a fresh pre-signed download URL."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found"
        )

    download_url = _presigned_url(row.storage_key) if row.storage_key else None

    return ReportResponse(
        id=row.id,
        type=row.type,
        status=row.status,
        download_url=download_url,
        expires_at=row.expires_at,
        created_at=row.created_at,
    )
