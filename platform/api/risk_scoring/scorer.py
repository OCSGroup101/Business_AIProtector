# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Endpoint risk scoring: XGBoost model with heuristic fallback.

The XGBoost model is loaded from RISK_MODEL_PATH (default: risk_model.pkl).
If the model file is absent or fails to load, the heuristic scorer is used.
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_RISK_TIERS = [
    (0.75, "CRITICAL"),
    (0.50, "HIGH"),
    (0.25, "MEDIUM"),
    (0.0, "LOW"),
]

# Lazy-loaded model handle
_model: Optional[object] = None
_model_loaded = False


def _load_model() -> Optional[object]:
    global _model, _model_loaded
    if _model_loaded:
        return _model

    _model_loaded = True
    model_path = Path(os.getenv("RISK_MODEL_PATH", "risk_model.pkl"))

    if not model_path.exists():
        logger.info(
            "Risk model not found at %s — using heuristic scorer", model_path
        )
        return None

    try:
        import joblib  # type: ignore[import-untyped]
        _model = joblib.load(model_path)
        logger.info("Loaded XGBoost risk model from %s", model_path)
        return _model
    except Exception as exc:
        logger.warning("Failed to load risk model: %s — using heuristic", exc)
        return None


def _feature_vector(features: dict[str, float]) -> list[float]:
    """Convert features dict to ordered list for XGBoost."""
    return [
        features.get("incidents_7d", 0.0),
        features.get("incidents_30d", 0.0),
        features.get("high_severity_7d", 0.0),
        features.get("unique_rules_7d", 0.0),
        features.get("incidents_1d", 0.0),
        features.get("open_incidents", 0.0),
        features.get("recency_spike", 0.0),
    ]


def _heuristic_score(features: dict[str, float]) -> float:
    """
    Weighted heuristic scoring when no trained model is available.
    Returns a score in [0.0, 1.0].
    """
    inc7 = min(features.get("incidents_7d", 0.0), 50.0)
    high = min(features.get("high_severity_7d", 0.0), 20.0)
    unique = min(features.get("unique_rules_7d", 0.0), 15.0)
    spike = min(features.get("recency_spike", 0.0), 10.0)
    open_inc = min(features.get("open_incidents", 0.0), 10.0)

    raw = (
        inc7 * 0.30
        + high * 1.0
        + unique * 0.50
        + spike * 1.5
        + open_inc * 0.40
    )

    # Normalize: cap at 30 for full score
    return min(raw / 30.0, 1.0)


def _tier(score: float) -> str:
    for threshold, tier in _RISK_TIERS:
        if score >= threshold:
            return tier
    return "LOW"


def score_agent(features: dict[str, float]) -> tuple[float, str]:
    """
    Score an agent given its features.

    Returns:
        (risk_score: float in [0.0, 1.0], risk_tier: str)
    """
    model = _load_model()

    if model is not None:
        try:
            import numpy as np  # type: ignore[import-untyped]
            vec = np.array([_feature_vector(features)], dtype=float)
            prob = float(model.predict_proba(vec)[0][1])  # P(high_risk)
            return prob, _tier(prob)
        except Exception as exc:
            logger.warning("XGBoost inference failed: %s — falling back to heuristic", exc)

    score = _heuristic_score(features)
    return score, _tier(score)
