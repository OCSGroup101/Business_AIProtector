# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
AlienVault OTX feed fetcher — polls every 4 hours.

Fetches recent pulse IOCs from the OTX DirectConnect API.
Requires an OTX API key set via the OTX_API_KEY environment variable.
If the key is absent, the feed skips silently (no error).

API reference: https://otx.alienvault.com/api
"""

import logging
import os
from datetime import datetime, timedelta, timezone

import httpx

from .scoring import compute_score

logger = logging.getLogger(__name__)

OTX_API_BASE = "https://otx.alienvault.com/api/v1"
# Only fetch pulses modified in the last window (avoids full catalog re-download)
OTX_LOOKBACK_HOURS = 8

# OTX indicator types mapped to our internal IOC types
_TYPE_MAP = {
    "FileHash-SHA256": "file_hash",
    "FileHash-MD5": None,  # MD5 only — skip; SHA-256 preferred
    "domain": "domain",
    "hostname": "domain",
    "IPv4": "ip_address",
    "IPv6": "ip_address",
    "URL": "url",
    "CVE": "cve",
}


async def fetch_otx_iocs() -> list[dict]:
    """
    Fetch IOCs from OTX pulses modified in the last OTX_LOOKBACK_HOURS hours.
    Returns an empty list if OTX_API_KEY is not configured.
    """
    api_key = os.getenv("OTX_API_KEY", "")
    if not api_key:
        logger.debug("OTX_API_KEY not set — OTX feed skipped")
        return []

    since = (
        datetime.now(tz=timezone.utc) - timedelta(hours=OTX_LOOKBACK_HOURS)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    headers = {"X-OTX-API-KEY": api_key}
    url = f"{OTX_API_BASE}/pulses/subscribed"
    params: dict[str, str] = {"modified_since": since, "limit": "50"}

    results: list[dict] = []
    seen: set[str] = set()

    try:
        async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:
            while url:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
                params = {}  # only for first request; pagination uses next URL

                for pulse in data.get("results", []):
                    pulse_tags = pulse.get("tags", [])
                    created_str = pulse.get("created", "")
                    try:
                        first_seen = datetime.strptime(
                            created_str[:19], "%Y-%m-%dT%H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                    except (ValueError, TypeError):
                        first_seen = datetime.now(tz=timezone.utc)

                    for indicator in pulse.get("indicators", []):
                        ioc_type = _TYPE_MAP.get(indicator.get("type", ""))
                        if not ioc_type:
                            continue
                        value = (indicator.get("indicator") or "").strip()
                        if not value:
                            continue

                        key = f"{ioc_type}:{value.lower()}"
                        if key in seen:
                            continue
                        seen.add(key)

                        sources = ["otx"]
                        score = compute_score(sources, first_seen)

                        results.append(
                            {
                                "ioc_type": ioc_type,
                                "value": value,
                                "score": score,
                                "sources": sources,
                                "tags": pulse_tags,
                                "first_seen": first_seen,
                                "metadata": {
                                    "pulse_name": pulse.get("name", ""),
                                    "pulse_id": pulse.get("id", ""),
                                    "description": (indicator.get("description") or "")[
                                        :256
                                    ],
                                },
                            }
                        )

                url = data.get("next")  # OTX pagination
    except Exception as exc:
        logger.error("OTX fetch failed: %s", exc)
        return []

    logger.info("OTX: fetched %d IOCs from pulse subscriptions", len(results))
    return results
