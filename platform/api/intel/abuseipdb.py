# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
AbuseIPDB feed fetcher — polls every 6 hours.

Fetches the top 10,000 most-reported IPs from the AbuseIPDB blacklist endpoint.
Requires ABUSEIPDB_API_KEY environment variable.
If the key is absent, the feed skips silently.

API reference: https://docs.abuseipdb.com/#blacklist-endpoint
"""

import logging
import os
from datetime import datetime, timezone

import httpx

from .scoring import compute_score

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"

# Minimum abuse confidence score (0–100) to include an IP
CONFIDENCE_THRESHOLD = 75


async def fetch_blacklist() -> list[dict]:
    """
    Fetch the AbuseIPDB blacklist (top abusive IPs by confidence score).
    Returns an empty list if ABUSEIPDB_API_KEY is not configured.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        logger.debug("ABUSEIPDB_API_KEY not set — AbuseIPDB feed skipped")
        return []

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": str(CONFIDENCE_THRESHOLD),
        "limit": "10000",
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(ABUSEIPDB_URL, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.error("AbuseIPDB fetch failed: %s", exc)
        return []

    now = datetime.now(tz=timezone.utc)
    sources = ["abuseipdb"]
    results: list[dict] = []

    for entry in data.get("data", []):
        ip = (entry.get("ipAddress") or "").strip()
        if not ip:
            continue

        confidence = entry.get("abuseConfidenceScore", 0)
        # Scale AbuseIPDB confidence (0–100) to a fractional score, then weight by base
        # base_weight(abuseipdb) = 0.75, cap at 1.0
        normalized = min(1.0, 0.75 * (confidence / 100) + 0.25)
        score = compute_score(sources, now) * (confidence / 100)
        score = round(max(score, normalized * 0.75), 4)

        country = entry.get("countryCode", "")
        usage_type = entry.get("usageType", "")
        isp = entry.get("isp", "")
        domain = entry.get("domain", "")

        tags: list[str] = []
        if usage_type:
            tags.append(usage_type.lower().replace(" ", "_"))
        if confidence >= 90:
            tags.append("high_confidence")

        results.append({
            "ioc_type": "ip_address",
            "value": ip,
            "score": score,
            "sources": sources,
            "tags": tags,
            "first_seen": now,
            "metadata": {
                "abuse_confidence": confidence,
                "country_code":     country,
                "usage_type":       usage_type,
                "isp":              isp,
                "domain":           domain,
                "total_reports":    entry.get("totalReports", 0),
                "last_reported_at": entry.get("lastReportedAt", ""),
            },
        })

    logger.info(
        "AbuseIPDB: fetched %d IPs (confidence >= %d%%)",
        len(results), CONFIDENCE_THRESHOLD,
    )
    return results
