# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
MISP (Malware Information Sharing Platform) feed fetcher.

Requires environment variables:
    MISP_URL  — e.g. https://misp.example.com
    MISP_KEY  — MISP auth key

Skipped silently when MISP_URL / MISP_KEY are not set.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

MISP_URL = os.environ.get("MISP_URL", "")
MISP_KEY = os.environ.get("MISP_KEY", "")

# IOC type mapping from MISP type to OpenClaw ioc_type
_TYPE_MAP: dict[str, str] = {
    "md5": "file_hash",
    "sha1": "file_hash",
    "sha256": "file_hash",
    "filename|md5": "file_hash",
    "filename|sha256": "file_hash",
    "domain": "domain",
    "hostname": "domain",
    "ip-dst": "ip",
    "ip-src": "ip",
    "url": "url",
    "uri": "url",
    "email-src": "email",
    "email-dst": "email",
}


async def fetch_misp_iocs() -> list[dict[str, Any]]:
    """
    Fetch recent MISP attributes from the last 7 days.
    Returns an empty list when MISP_URL/MISP_KEY are not configured.
    """
    if not MISP_URL or not MISP_KEY:
        logger.debug("MISP feed skipped: MISP_URL or MISP_KEY not set")
        return []

    since = (datetime.now(tz=timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    url = f"{MISP_URL.rstrip('/')}/attributes/restSearch"
    payload = {
        "returnFormat": "json",
        "type": list(_TYPE_MAP.keys()),
        "timestamp": since,
        "limit": 5000,
        "to_ids": 1,
    }
    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    iocs: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=60, verify=True) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    for attr in data.get("response", {}).get("Attribute", []):
        misp_type = attr.get("type", "")
        ioc_type = _TYPE_MAP.get(misp_type)
        if not ioc_type:
            continue

        value = attr.get("value", "")
        # For compound types like "filename|sha256", extract the hash
        if "|" in misp_type and "|" in value:
            value = value.split("|")[-1]
        if not value:
            continue

        iocs.append(
            {
                "ioc_type": ioc_type,
                "value": value,
                "score": 0.85,
                "sources": ["misp"],
                "tags": attr.get("tags", []),
                "metadata": {
                    "misp_event_id": attr.get("event_id"),
                    "misp_attr_id": attr.get("id"),
                    "misp_comment": attr.get("comment", "")[:256],
                },
            }
        )

    logger.info("MISP feed: fetched %d IOCs", len(iocs))
    return iocs


# Environment variable for the MISP event that receives pushed IOCs
MISP_PUSH_EVENT_ID = os.environ.get("MISP_PUSH_EVENT_ID", "")

# Reverse map: OpenClaw ioc_type → MISP attribute type used when pushing
_REVERSE_TYPE_MAP: dict[str, str] = {
    "file_hash": "sha256",
    "domain": "domain",
    "ip": "ip-dst",
    "url": "url",
    "email": "email-src",
}


async def push_ioc_to_misp(ioc: dict[str, Any]) -> bool:
    """
    Push a verified high-confidence IOC back to the MISP instance.
    Used for bi-directional sharing — OpenClaw contributed IOCs enrich MISP.
    Only pushes IOCs with score >= 0.90 and verification_status = 'verified'.
    Returns True on success.
    """
    if not MISP_URL or not MISP_KEY:
        logger.debug("MISP push skipped: MISP_URL or MISP_KEY not set")
        return False

    score = ioc.get("score", 0.0)
    verification_status = ioc.get("verification_status", "")
    if score < 0.90 or verification_status != "verified":
        logger.debug(
            "MISP push skipped: score=%.2f status=%s (requires score>=0.90 and verified)",
            score,
            verification_status,
        )
        return False

    ioc_type = ioc.get("ioc_type", "")
    misp_type = _REVERSE_TYPE_MAP.get(ioc_type, "text")
    value = ioc.get("value", "")
    if not value:
        return False

    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # If a dedicated push event ID is configured, add to that event.
    # Otherwise, create a new minimal MISP event to host this IOC.
    if MISP_PUSH_EVENT_ID:
        url = f"{MISP_URL.rstrip('/')}/attributes/add/{MISP_PUSH_EVENT_ID}"
        payload: dict[str, Any] = {
            "type": misp_type,
            "value": value,
            "to_ids": 1,
            "comment": f"Contributed by OpenClaw (score={score:.2f})",
        }
    else:
        # Create a new event with the IOC embedded
        url = f"{MISP_URL.rstrip('/')}/events/add"
        payload = {
            "info": f"OpenClaw contributed IOC: {ioc_type} {value[:64]}",
            "distribution": 0,  # organisation only
            "threat_level_id": 2,  # medium
            "analysis": 2,  # completed
            "Attribute": [
                {
                    "type": misp_type,
                    "value": value,
                    "to_ids": 1,
                    "comment": f"Contributed by OpenClaw (score={score:.2f})",
                }
            ],
        }

    try:
        async with httpx.AsyncClient(timeout=30, verify=True) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            logger.info(
                "MISP push succeeded: ioc_type=%s value=%s score=%.2f",
                ioc_type,
                value[:64],
                score,
            )
            return True
    except Exception as exc:
        logger.warning("MISP push failed for %s=%s: %s", ioc_type, value[:64], exc)
        return False
