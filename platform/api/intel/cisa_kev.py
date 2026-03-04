# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""CISA KEV feed fetcher — polls daily, extracts known-exploited CVEs."""

import logging
from datetime import datetime, timezone

import httpx

from .scoring import compute_score

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev_entries() -> list[dict]:
    """
    Fetch CISA Known Exploited Vulnerabilities catalog.

    Returns IOC dicts of type "cve":
      {
        "ioc_type":   "cve",
        "value":      "CVE-2024-XXXXX",
        "score":      0.95,
        "sources":    ["cisa_kev"],
        "tags":       ["ransomware"],
        "first_seen": datetime,
        "metadata":   {
            "vendor_project": "...",
            "product": "...",
            "vulnerability_name": "...",
            "short_description": "...",
            "required_action": "...",
            "due_date": "...",
            "known_ransomware_use": true/false,
        }
      }
    """
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.error("CISA KEV fetch failed: %s", exc)
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        logger.warning("CISA KEV: empty vulnerabilities list")
        return []

    results: list[dict] = []
    sources = ["cisa_kev"]

    for entry in vulnerabilities:
        cve_id = (entry.get("cveID") or "").strip()
        if not cve_id or not cve_id.startswith("CVE-"):
            continue

        date_added_str = entry.get("dateAdded", "")
        try:
            first_seen = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            first_seen = datetime.now(tz=timezone.utc)

        score = compute_score(sources, first_seen)

        # CISA marks ransomware-associated entries
        ransomware_use = entry.get("knownRansomwareCampaignUse", "Unknown")
        tags: list[str] = []
        if ransomware_use == "Known":
            tags.append("ransomware")
        tags.append("actively-exploited")

        results.append(
            {
                "ioc_type": "cve",
                "value": cve_id,
                "score": score,
                "sources": sources,
                "tags": tags,
                "first_seen": first_seen,
                "metadata": {
                    "vendor_project": entry.get("vendorProject", ""),
                    "product": entry.get("product", ""),
                    "vulnerability_name": entry.get("vulnerabilityName", ""),
                    "short_description": entry.get("shortDescription", ""),
                    "required_action": entry.get("requiredAction", ""),
                    "due_date": entry.get("dueDate", ""),
                    "known_ransomware_use": ransomware_use,
                },
            }
        )

    logger.info("CISA KEV: fetched %d CVE entries", len(results))
    return results
