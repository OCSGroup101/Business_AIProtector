# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Unit tests for the OpenClaw Integration SDK client and SIEM connectors."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import respx
import httpx

from openclaw_sdk import OpenClawClient
from openclaw_sdk.models import Incident
from openclaw_sdk.siem import SplunkHecConnector, ElasticsearchConnector


FAKE_INCIDENT = {
    "id": "01HZTEST00000000001",
    "tenant_id": "test_tenant",
    "agent_id": "agent_001",
    "hostname": "test-host",
    "rule_id": "OC-TEST-0001",
    "rule_name": "Test Rule",
    "severity": "HIGH",
    "status": "OPEN",
    "mitre_techniques": ["T1059.001"],
    "first_seen_at": "2026-03-08T10:00:00Z",
    "last_seen_at": "2026-03-08T10:01:00Z",
}


# ── Incident model ────────────────────────────────────────────────────────────

class TestIncidentModel:
    def test_parse_incident(self):
        inc = Incident.model_validate(FAKE_INCIDENT)
        assert inc.id == "01HZTEST00000000001"
        assert inc.severity == "HIGH"
        assert inc.is_active()

    def test_resolved_incident_not_active(self):
        data = {**FAKE_INCIDENT, "status": "RESOLVED"}
        inc = Incident.model_validate(data)
        assert not inc.is_active()

    def test_to_siem_dict_flattens_techniques(self):
        inc = Incident.model_validate(FAKE_INCIDENT)
        d = inc.to_siem_dict()
        assert d["mitre_techniques"] == "T1059.001"
        assert d["openclaw_incident_id"] == inc.id


# ── Platform API client ───────────────────────────────────────────────────────

class TestOpenClawClient:
    @pytest.mark.asyncio
    async def test_list_incidents_parses_response(self):
        with respx.mock(base_url="http://test") as mock:
            mock.get("/api/v1/incidents").mock(
                return_value=httpx.Response(200, json=[FAKE_INCIDENT])
            )
            async with OpenClawClient("http://test", token="test-token") as c:
                incidents = await c.list_incidents()
            assert len(incidents) == 1
            assert incidents[0].rule_name == "Test Rule"

    @pytest.mark.asyncio
    async def test_health_check(self):
        with respx.mock(base_url="http://test") as mock:
            mock.get("/health/ready").mock(
                return_value=httpx.Response(200, json={"status": "ready"})
            )
            async with OpenClawClient("http://test", token="tok") as c:
                result = await c.health()
            assert result["status"] == "ready"


# ── Splunk HEC connector ──────────────────────────────────────────────────────

class TestSplunkHecConnector:
    @pytest.mark.asyncio
    async def test_send_event_returns_true_on_200(self):
        with respx.mock() as mock:
            mock.post("https://splunk:8088/services/collector/event").mock(
                return_value=httpx.Response(200, json={"text": "Success", "code": 0})
            )
            async with SplunkHecConnector(
                url="https://splunk:8088", token="test-token"
            ) as s:
                ok = await s.send_event({"message": "test", "hostname": "host1"})
            assert ok is True

    @pytest.mark.asyncio
    async def test_send_incident_returns_true(self):
        inc = Incident.model_validate(FAKE_INCIDENT)
        with respx.mock() as mock:
            mock.post("https://splunk:8088/services/collector/event").mock(
                return_value=httpx.Response(200, json={"text": "Success"})
            )
            async with SplunkHecConnector(
                url="https://splunk:8088", token="test-token"
            ) as s:
                ok = await s.send_incident(inc)
            assert ok is True

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self):
        with respx.mock() as mock:
            mock.post("https://splunk:8088/services/collector/event").mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            async with SplunkHecConnector(
                url="https://splunk:8088", token="test-token"
            ) as s:
                ok = await s.send_event({"message": "test"})
            assert ok is False


# ── Elasticsearch connector ───────────────────────────────────────────────────

class TestElasticsearchConnector:
    @pytest.mark.asyncio
    async def test_test_connection_ok(self):
        with respx.mock() as mock:
            mock.get("https://es:9200/_cluster/health").mock(
                return_value=httpx.Response(200, json={"status": "green"})
            )
            async with ElasticsearchConnector(
                url="https://es:9200", api_key="test-key"
            ) as es:
                ok = await es.test_connection()
            assert ok is True
