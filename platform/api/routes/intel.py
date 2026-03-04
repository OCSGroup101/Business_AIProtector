"""Intelligence / IOC management endpoints."""

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, Query, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..models.intel import IocEntry
from ..models.global_ioc import GlobalIocEntry
from ..middleware.rbac import Permission, require_permission
from ..intel.scoring import INCLUSION_THRESHOLD
from ..intel.feed_registry import FEED_REGISTRY

logger = logging.getLogger(__name__)

router = APIRouter()


class IocSummary(BaseModel):
    id: str
    ioc_type: str
    value: str
    confidence: float
    sources: Optional[list] = None
    is_active: bool
    last_seen: datetime


@router.get("/iocs", response_model=list[IocSummary])
async def list_iocs(
    ioc_type: Optional[str] = Query(None),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
    _role=Depends(require_permission(Permission.INTEL_READ)),
) -> list[IocSummary]:
    query = select(IocEntry).where(IocEntry.is_active.is_(True)).limit(limit)
    if ioc_type:
        query = query.where(IocEntry.ioc_type == ioc_type)
    if min_confidence > 0:
        query = query.where(IocEntry.confidence >= min_confidence)

    result = await db.execute(query)
    return [
        IocSummary(
            id=i.id, ioc_type=i.ioc_type, value=i.value,
            confidence=i.confidence, sources=i.sources,
            is_active=i.is_active, last_seen=i.last_seen,
        )
        for i in result.scalars()
    ]


@router.get("/feeds", status_code=status.HTTP_200_OK)
async def list_feeds(
    _role=Depends(require_permission(Permission.INTEL_READ)),
) -> dict:
    """List configured intelligence feeds and their current status."""
    feeds = []
    for entry in FEED_REGISTRY.values():
        record: dict = {
            "name": entry.name,
            "interval": entry.interval,
            "status": entry.status,
        }
        if entry.last_run is not None:
            record["last_run"] = entry.last_run.isoformat()
            record["last_count"] = entry.last_count
        if entry.last_error is not None:
            record["last_error"] = entry.last_error
        feeds.append(record)
    return {"feeds": feeds}


@router.get("/ioc-bundle", status_code=status.HTTP_200_OK)
async def get_ioc_bundle(
    since: Optional[datetime] = Query(None, description="Only return IOCs updated after this UTC timestamp"),
    x_agent_id: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """
    Return active global IOCs as NDJSON for agent consumption.

    Each line is one of:
      {"action":"upsert","type":"file_hash","value":"abc...","score":0.90,"metadata":{...}}
      {"action":"delete","type":"file_hash","value":"def..."}

    Agents poll this endpoint every 5 minutes, passing X-Last-Bundle-Time to receive deltas.
    No auth required for enrolled agents (validated via mTLS at the gateway layer).
    """
    query = select(GlobalIocEntry).where(GlobalIocEntry.score >= INCLUSION_THRESHOLD)
    if since is not None:
        query = query.where(GlobalIocEntry.updated_at >= since)

    result = await db.execute(query)
    rows = result.scalars().all()

    lines = []
    for row in rows:
        action = "upsert" if row.is_active else "delete"
        record: dict = {"action": action, "type": row.ioc_type, "value": row.value_lower}
        if action == "upsert":
            record["score"] = row.score
            record["metadata"] = row.feed_metadata or {}
        lines.append(json.dumps(record, separators=(",", ":")))

    logger.debug("IOC bundle: %d records for agent %s (since=%s)", len(lines), x_agent_id, since)
    return Response(
        content="\n".join(lines),
        media_type="application/x-ndjson",
        headers={"X-IOC-Count": str(len(lines))},
    )
