# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""IOC confidence scoring — formula from threat-intelligence agent spec.

score = base_weight × multi_source_bonus × age_decay_factor
  base_weight   : per-feed constant (MalwareBazaar = 0.90)
  multi_source  : +0.10 bonus if seen in ≥2 sources (capped at 1.0)
  age_decay     : ×0.85 if first_seen > 90 days ago
  threshold     : 0.50 required for LMDB inclusion, 0.85 = HIGH confidence
"""

from datetime import datetime, timezone

# Per-feed base weights
FEED_BASE_WEIGHTS: dict[str, float] = {
    "malwarebazaar": 0.90,
    "urlhaus": 0.85,
    "cisa_kev": 0.95,
    "otx": 0.80,
    "misp": 0.85,
    "abuseipdb": 0.75,
    "mitre": 0.60,
}

MULTI_SOURCE_BONUS = 0.10
AGE_DECAY_FACTOR = 0.85
AGE_DECAY_DAYS = 90
INCLUSION_THRESHOLD = 0.50
HIGH_CONFIDENCE_THRESHOLD = 0.85


def compute_score(
    sources: list[str],
    first_seen: datetime,
) -> float:
    """Compute a confidence score in [0.0, 1.0] for an IOC."""
    if not sources:
        return 0.0

    # Base weight from highest-weight source present
    base = max(
        FEED_BASE_WEIGHTS.get(s, 0.60) for s in sources
    )

    # Multi-source bonus
    bonus = MULTI_SOURCE_BONUS if len(sources) >= 2 else 0.0
    raw = min(1.0, base + bonus)

    # Age decay
    now = datetime.now(tz=timezone.utc)
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    age_days = (now - first_seen).days
    if age_days > AGE_DECAY_DAYS:
        raw *= AGE_DECAY_FACTOR

    return round(raw, 4)


def meets_threshold(score: float) -> bool:
    return score >= INCLUSION_THRESHOLD
