# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
TAXII 2.1 client — polls a STIX collection with added_after cursor.

Supports: TAXII 2.1 (RFC compliant).
Authentication: Bearer token (api_key_encrypted decrypted at runtime).
"""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# STIX indicator type → OpenClaw ioc_type
_STIX_PATTERN_MAP = {
    "file:hashes.'MD5'": "file_hash",
    "file:hashes.'SHA-1'": "file_hash",
    "file:hashes.'SHA-256'": "file_hash",
    "file:hashes.MD5": "file_hash",
    "file:hashes.SHA-256": "file_hash",
    "domain-name:value": "domain",
    "ipv4-addr:value": "ip",
    "ipv6-addr:value": "ip",
    "url:value": "url",
    "email-addr:value": "email",
}


async def poll_taxii_collection(
    taxii_url: str,
    collection_id: str,
    api_key: str,
    added_after: Optional[datetime] = None,
) -> tuple[list[dict[str, Any]], Optional[datetime]]:
    """
    Poll a TAXII 2.1 collection for new STIX objects.

    Returns:
        (iocs, max_added_after) — iocs list for upsert, new cursor for next poll.
    """
    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Authorization": f"Bearer {api_key}",
    }
    base = taxii_url.rstrip("/")
    url = f"{base}/api/v21/collections/{collection_id}/objects/"

    params: dict[str, str] = {}
    if added_after:
        params["added_after"] = added_after.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    iocs: list[dict[str, Any]] = []
    max_added: Optional[datetime] = None

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        bundle = resp.json()

    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        ioc_type, value = _extract_from_pattern(pattern)
        if not ioc_type or not value:
            continue

        added_str = obj.get("created") or obj.get("modified", "")
        try:
            obj_added = datetime.fromisoformat(added_str.replace("Z", "+00:00"))
            if max_added is None or obj_added > max_added:
                max_added = obj_added
        except ValueError:
            pass

        iocs.append(
            {
                "ioc_type": ioc_type,
                "value": value,
                "score": 0.75,
                "sources": ["taxii"],
                "tags": obj.get("labels", []),
                "metadata": {
                    "stix_id": obj.get("id"),
                    "stix_name": obj.get("name", ""),
                    "taxii_url": taxii_url,
                    "collection_id": collection_id,
                },
            }
        )

    logger.info(
        "TAXII poll (%s/%s): %d indicators", taxii_url, collection_id, len(iocs)
    )
    return iocs, max_added


def _extract_from_pattern(pattern: str) -> tuple[Optional[str], Optional[str]]:
    """
    Extract (ioc_type, value) from a simple STIX pattern string.
    Only handles single-comparison patterns like:
        [domain-name:value = 'evil.example.com']
    """
    import re

    m = re.search(r"\[(.+?)\s*=\s*'(.+?)'\]", pattern)
    if not m:
        return None, None

    field = m.group(1).strip()
    value = m.group(2).strip()

    ioc_type = _STIX_PATTERN_MAP.get(field)
    return ioc_type, value if ioc_type else None
