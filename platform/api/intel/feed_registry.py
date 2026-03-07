# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Feed status registry — shared in-memory state for feed health tracking.

All feed loops write here; the /api/v1/intel/feeds route reads from here.
Asyncio-safe: all writes happen from the same event loop.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class FeedStatus:
    name: str
    interval: str
    status: str = "pending"  # pending | active | error
    last_run: Optional[datetime] = None
    last_count: int = 0
    last_error: Optional[str] = None


# Registry keyed by feed name (matches names used in /api/v1/intel/feeds response)
FEED_REGISTRY: dict[str, FeedStatus] = {
    "cisa_kev": FeedStatus(name="CISA KEV", interval="daily"),
    "malwarebazaar": FeedStatus(name="MalwareBazaar", interval="4h"),
    "urlhaus": FeedStatus(name="URLHaus", interval="2h"),
    "otx": FeedStatus(name="OTX", interval="4h"),
    "misp": FeedStatus(name="MISP", interval="1h"),
    "abuseipdb": FeedStatus(name="AbuseIPDB", interval="6h"),
    "mitre": FeedStatus(name="MITRE ATT&CK", interval="weekly"),
}


def mark_success(feed_key: str, count: int) -> None:
    from datetime import timezone

    entry = FEED_REGISTRY.get(feed_key)
    if entry:
        entry.status = "active"
        entry.last_run = datetime.now(tz=timezone.utc)
        entry.last_count = count
        entry.last_error = None


def mark_error(feed_key: str, error: str) -> None:
    from datetime import timezone

    entry = FEED_REGISTRY.get(feed_key)
    if entry:
        entry.status = "error"
        entry.last_run = datetime.now(tz=timezone.utc)
        entry.last_error = str(error)[:256]
