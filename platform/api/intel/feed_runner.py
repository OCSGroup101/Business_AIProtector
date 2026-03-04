# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Background feed runner — schedules all configured threat intelligence fetchers."""

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..database import AsyncSessionLocal
from ..models.global_ioc import GlobalIocEntry
from .malwarebazaar import fetch_recent_hashes
from .scoring import meets_threshold

logger = logging.getLogger(__name__)

# Feed intervals in seconds
MALWAREBAZAAR_INTERVAL = 4 * 3600   # 4 hours


async def _upsert_iocs(iocs: list[dict]) -> int:
    """
    Upsert a list of IOC dicts into public.global_ioc_entries.
    On conflict (ioc_type, value_lower): update score, last_seen, sources, tags, metadata.
    Returns number of rows upserted.
    """
    if not iocs:
        return 0

    now = datetime.now(tz=timezone.utc)
    rows = []
    for ioc in iocs:
        if not meets_threshold(ioc["score"]):
            continue
        value_lower = ioc["value"].lower()
        # Generate a stable ULID-style ID from type+value — use first 26 chars of hex sha
        import hashlib
        raw_id = hashlib.sha256(f"{ioc['ioc_type']}:{value_lower}".encode()).hexdigest()[:26]
        rows.append(
            {
                "id": raw_id,
                "ioc_type": ioc["ioc_type"],
                "value": ioc["value"],
                "value_lower": value_lower,
                "score": ioc["score"],
                "sources": ioc.get("sources"),
                "tags": ioc.get("tags"),
                "feed_metadata": ioc.get("metadata"),
                "first_seen": ioc.get("first_seen", now),
                "last_seen": now,
                "is_active": True,
                "created_at": now,
                "updated_at": now,
            }
        )

    if not rows:
        return 0

    async with AsyncSessionLocal() as session:
        stmt = pg_insert(GlobalIocEntry).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_global_ioc_type_value",
            set_={
                "score": stmt.excluded.score,
                "last_seen": stmt.excluded.last_seen,
                "sources": stmt.excluded.sources,
                "tags": stmt.excluded.tags,
                "feed_metadata": stmt.excluded.feed_metadata,
                "is_active": True,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        await session.execute(stmt)
        await session.commit()

    return len(rows)


async def _run_malwarebazaar_loop() -> None:
    """Runs the MalwareBazaar feed in an infinite loop with MALWAREBAZAAR_INTERVAL delay."""
    logger.info("MalwareBazaar feed runner started (interval=%ds)", MALWAREBAZAAR_INTERVAL)
    while True:
        try:
            iocs = await fetch_recent_hashes()
            count = await _upsert_iocs(iocs)
            logger.info("MalwareBazaar: upserted %d IOCs into global store", count)
        except Exception:
            logger.exception("MalwareBazaar feed runner error — will retry next cycle")
        await asyncio.sleep(MALWAREBAZAAR_INTERVAL)


def start_feed_tasks() -> list[asyncio.Task]:
    """
    Launch all feed background tasks and return their Task handles.
    Call from the FastAPI lifespan after app startup.
    """
    tasks = [
        asyncio.create_task(_run_malwarebazaar_loop(), name="feed:malwarebazaar"),
    ]
    logger.info("Threat intelligence feed tasks started (%d feeds)", len(tasks))
    return tasks
