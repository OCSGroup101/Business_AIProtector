# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""URLHaus feed fetcher — polls every 2 hours, extracts malicious URLs and domains."""

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .scoring import compute_score

logger = logging.getLogger(__name__)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
FETCH_LIMIT = 1000


async def fetch_recent_urls() -> list[dict]:
    """
    Fetch recent malicious URLs from URLHaus (abuse.ch).

    Returns IOC dicts for both the full URL and its domain/IP, deduplicated:
      {
        "ioc_type":   "url" | "domain" | "ip_address",
        "value":      "...",
        "score":      0.85,
        "sources":    ["urlhaus"],
        "tags":       ["..."],
        "first_seen": datetime,
        "metadata":   {...}
      }
    """
    payload = {"query": "get_recent_urls", "limit": str(FETCH_LIMIT)}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(URLHAUS_API, data=payload)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.error("URLHaus fetch failed: %s", exc)
        return []

    if data.get("query_status") not in ("ok", "is_ok"):
        logger.warning("URLHaus returned status: %s", data.get("query_status"))
        return []

    results: list[dict] = []
    seen: set[str] = set()

    for entry in data.get("urls", []):
        url = (entry.get("url") or "").strip()
        if not url:
            continue

        # Parse first-seen timestamp from "YYYY-MM-DD HH:MM:SS" UTC
        first_seen_str = entry.get("date_added", "")
        try:
            first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            first_seen = datetime.now(tz=timezone.utc)

        tags: list[str] = []
        for tag_entry in entry.get("tags") or []:
            if isinstance(tag_entry, str):
                tags.append(tag_entry)
            elif isinstance(tag_entry, dict):
                tags.append(tag_entry.get("tag", ""))

        sources = ["urlhaus"]
        score = compute_score(sources, first_seen)

        meta = {
            "id": entry.get("id", ""),
            "threat": entry.get("threat", ""),
            "url_status": entry.get("url_status", ""),
            "tags": tags,
            "urlhaus_link": entry.get("urlhaus_reference", ""),
        }

        # Emit URL IOC
        url_key = f"url:{url.lower()}"
        if url_key not in seen:
            seen.add(url_key)
            results.append({
                "ioc_type": "url",
                "value": url,
                "score": score,
                "sources": sources,
                "tags": tags,
                "first_seen": first_seen,
                "metadata": meta,
            })

        # Emit domain or IP IOC extracted from the URL
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        except Exception:
            host = ""

        if host:
            ioc_type = "ip_address" if _is_ip(host) else "domain"
            host_key = f"{ioc_type}:{host.lower()}"
            if host_key not in seen:
                seen.add(host_key)
                results.append({
                    "ioc_type": ioc_type,
                    "value": host,
                    "score": score,
                    "sources": sources,
                    "tags": tags,
                    "first_seen": first_seen,
                    "metadata": {"url_count": 1, "threat": entry.get("threat", "")},
                })

    logger.info("URLHaus: fetched %d IOCs from %d URLs", len(results), len(data.get("urls", [])))
    return results


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
