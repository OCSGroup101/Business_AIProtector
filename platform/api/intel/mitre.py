# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
MITRE ATT&CK STIX feed fetcher.

Downloads the MITRE ATT&CK Enterprise matrix from the official GitHub release,
extracts technique IDs/names, and stores them as ioc_type="mitre_technique"
with score=1.0 so they appear in the IOC bundle for agent-side reference.

Source: https://github.com/mitre/cti/enterprise-attack/enterprise-attack.json
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


async def fetch_mitre_techniques() -> list[dict[str, Any]]:
    """
    Fetch all ATT&CK Enterprise techniques and return as IOC dicts.
    Returns an empty list on network error (non-fatal feed failure).
    """
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(_STIX_URL)
            resp.raise_for_status()
            stix = resp.json()
    except Exception as exc:
        logger.warning("MITRE ATT&CK fetch failed: %s", exc)
        return []

    iocs: list[dict[str, Any]] = []
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract technique ID (T1234 or T1234.001 format)
        external = obj.get("external_references", [])
        technique_id = next(
            (
                ref["external_id"]
                for ref in external
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not technique_id:
            continue

        name = obj.get("name", technique_id)
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        iocs.append(
            {
                "ioc_type": "mitre_technique",
                "value": technique_id,
                "score": 1.0,
                "sources": ["mitre_attack"],
                "tags": tactics,
                "metadata": {
                    "name": name,
                    "stix_id": obj.get("id"),
                    "tactics": tactics,
                    "platforms": obj.get("x_mitre_platforms", []),
                },
            }
        )

    logger.info("MITRE ATT&CK feed: fetched %d techniques", len(iocs))
    return iocs
