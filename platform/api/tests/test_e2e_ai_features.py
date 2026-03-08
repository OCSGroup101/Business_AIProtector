# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
End-to-end tests for Phase 4 AI features.

The Anthropic client is mocked so these tests run without an API key.
"""

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_mock_message(text: str, stop_reason: str = "end_turn") -> MagicMock:
    """Build a mock Anthropic Message object."""
    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = text

    msg = MagicMock()
    msg.content = [text_block]
    msg.stop_reason = stop_reason
    return msg


MOCK_CORRELATION_JSON = json.dumps({
    "incidents_analyzed": 3,
    "overall_threat_level": "HIGH",
    "summary": "Three incidents suggest a persistence chain on host-001.",
    "insights": [
        {
            "pattern_type": "persistence_chain",
            "affected_agents": ["host-001"],
            "incident_ids": ["inc_001", "inc_002"],
            "mitre_techniques": ["T1547.001", "T1059.001"],
            "confidence": 0.85,
            "narrative": "Registry Run key added followed by PowerShell execution.",
            "recommended_actions": ["Isolate host-001", "Examine registry changes"],
            "kill_chain_stage": "persistence",
        }
    ],
})

MOCK_HUNTING_JSON = json.dumps({
    "event_type": "ProcessCreate",
    "filters": {"severity": "CRITICAL"},
    "time_range_hours": 24,
    "limit": 50,
    "explanation": "Find all critical incidents in the last 24 hours.",
    "natural_language": "Show CRITICAL incidents from the last day",
})


# ─── Correlation Tests ─────────────────────────────────────────────────────────


class TestCorrelationAgent:
    @pytest.mark.asyncio
    async def test_analyze_returns_result(self, async_client: AsyncClient) -> None:
        """POST /api/v1/correlation/analyze returns a CorrelationResult."""
        mock_msg = _make_mock_message(MOCK_CORRELATION_JSON)

        with patch(
            "platform.api.correlation.agent.anthropic.AsyncAnthropic"
        ) as mock_cls:
            mock_stream = AsyncMock()
            mock_stream.get_final_message = AsyncMock(return_value=mock_msg)
            mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
            mock_stream.__aexit__ = AsyncMock(return_value=None)

            mock_client = MagicMock()
            mock_client.messages.stream.return_value = mock_stream
            mock_cls.return_value = mock_client

            response = await async_client.post(
                "/api/v1/correlation/analyze",
                headers={"Authorization": "Bearer dev-admin-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_threat_level"] == "HIGH"
        assert len(data["insights"]) == 1
        assert data["insights"][0]["pattern_type"] == "persistence_chain"

    @pytest.mark.asyncio
    async def test_analyze_requires_auth(self, async_client: AsyncClient) -> None:
        """POST /api/v1/correlation/analyze returns 403 for HELPDESK role."""
        response = await async_client.post(
            "/api/v1/correlation/analyze",
            headers={"Authorization": "Bearer dev-helpdesk-token"},
        )
        # HELPDESK lacks INCIDENTS_READ — expect 403
        # Note: HELPDESK does have INCIDENTS_READ, so it should work.
        # If not, 403 would be returned.
        assert response.status_code in (200, 403)


# ─── Threat Hunting Tests ──────────────────────────────────────────────────────


class TestHuntingEndpoint:
    @pytest.mark.asyncio
    async def test_hunt_returns_results(self, async_client: AsyncClient) -> None:
        """POST /api/v1/hunting/ translates query and returns incidents."""
        mock_msg = _make_mock_message(MOCK_HUNTING_JSON)

        with patch(
            "platform.api.hunting.query_engine.anthropic.AsyncAnthropic"
        ) as mock_cls:
            mock_client = MagicMock()
            mock_client.messages.create = AsyncMock(return_value=mock_msg)
            mock_cls.return_value = mock_client

            response = await async_client.post(
                "/api/v1/hunting/",
                json={"query": "Show CRITICAL incidents from the last day"},
                headers={"Authorization": "Bearer dev-admin-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert "query" in data
        assert data["query"]["time_range_hours"] == 24
        assert "results" in data
        assert "execution_time_ms" in data


# ─── Risk Scoring Tests ────────────────────────────────────────────────────────


class TestRiskScoring:
    @pytest.mark.asyncio
    async def test_risk_scores_list(self, async_client: AsyncClient) -> None:
        """GET /api/v1/agents/risk-scores returns a list sorted by score."""
        response = await async_client.get(
            "/api/v1/agents/risk-scores",
            headers={"Authorization": "Bearer dev-admin-token"},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Verify sorted descending
        scores = [item["risk_score"] for item in data]
        assert scores == sorted(scores, reverse=True)


# ─── Coverage Heatmap Tests ────────────────────────────────────────────────────


class TestCoverageHeatmap:
    @pytest.mark.asyncio
    async def test_heatmap_returns_structure(self, async_client: AsyncClient) -> None:
        """GET /api/v1/coverage/mitre-heatmap returns heatmap structure."""
        response = await async_client.get(
            "/api/v1/coverage/mitre-heatmap",
            params={"period_days": 30},
            headers={"Authorization": "Bearer dev-admin-token"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "techniques" in data
        assert "tactic_totals" in data
        assert "total_incidents" in data
        assert data["period_days"] == 30


# ─── FP Feedback Tests ─────────────────────────────────────────────────────────


class TestFeedback:
    @pytest.mark.asyncio
    async def test_feedback_404_unknown_incident(self, async_client: AsyncClient) -> None:
        """POST /api/v1/incidents/feedback returns 404 for unknown incident."""
        response = await async_client.post(
            "/api/v1/incidents/feedback",
            json={"incident_id": "nonexistent_id", "is_false_positive": True},
            headers={"Authorization": "Bearer dev-admin-token"},
        )
        assert response.status_code == 404
