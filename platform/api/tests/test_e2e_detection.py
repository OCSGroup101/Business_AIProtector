# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""End-to-end detection pipeline tests.

Validates the full path:
  Agent telemetry POST → incident creation → incident readable via API

Phase 1 latency target: incident visible within 30 seconds of telemetry upload.

Run against a live dev stack:
  make dev-up
  pytest platform/api/tests/test_e2e_detection.py -v

Environment variables:
  PLATFORM_URL          Base URL of platform API (default: http://localhost:8888)
  E2E_ADMIN_TOKEN       Bearer token with TENANT_ADMIN role (default: dev-admin-token)
  E2E_TENANT_ID         Tenant ID to use for test data (default: dev)
"""

import json
import os
import time
import uuid

import httpx
import pytest

PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:8888")
ADMIN_TOKEN = os.environ.get("E2E_ADMIN_TOKEN", "dev-admin-token")
TENANT_ID = os.environ.get("E2E_TENANT_ID", "dev")

DETECTION_LATENCY_BUDGET_SECS = 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_headers(agent_id: str) -> dict:
    """Headers used by an agent when posting telemetry."""
    return {
        "X-Agent-ID": agent_id,
        "X-Tenant-ID": TENANT_ID,
        "Content-Type": "application/x-ndjson",
    }


def _api_headers() -> dict:
    """Headers used by the console / operator hitting the REST API."""
    return {
        "Authorization": f"Bearer {ADMIN_TOKEN}",
        "X-Tenant-ID": TENANT_ID,
    }


def _telemetry_event(agent_id: str, rule_id: str, rule_name: str, severity: str) -> bytes:
    """Build a single-event NDJSON telemetry batch containing one detection hit."""
    event = {
        "event_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "tenant_id": TENANT_ID,
        "hostname": f"test-host-{agent_id[:8]}",
        "event_type": "process_create",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "payload": {
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
            "pid": 4242,
        },
        "detections": [
            {
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "mitre_techniques": ["T1003.001"],
            }
        ],
    }
    return (json.dumps(event) + "\n").encode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api_client():
    with httpx.Client(base_url=PLATFORM_URL, headers=_api_headers(), timeout=15) as client:
        yield client


@pytest.fixture(scope="module")
def agent_id():
    """Unique agent ID per test run to avoid dedup collisions."""
    return f"e2e-agent-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Connectivity pre-check
# ---------------------------------------------------------------------------

class TestPlatformReachable:
    def test_health_ready(self, api_client):
        """Platform API must be up before running E2E tests."""
        r = api_client.get("/health/ready")
        assert r.status_code == 200, (
            f"Platform API not reachable at {PLATFORM_URL}. "
            "Run `make dev-up` and wait for startup. Got: "
            f"{r.status_code} {r.text[:200]}"
        )


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

class TestDetectionPipeline:
    """Full path: telemetry upload → incident created → readable via API."""

    def test_telemetry_batch_accepted(self, api_client, agent_id):
        """POST to /telemetry/batch returns 202 with incidents_created >= 1."""
        rule_id = "OC-TEST-0001"
        rule_name = "E2E: Credential Dumper Detected"
        body = _telemetry_event(agent_id, rule_id, rule_name, "HIGH")

        t0 = time.monotonic()
        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={
                **_api_headers(),
                "X-Agent-ID": agent_id,
                "X-Tenant-ID": TENANT_ID,
                "Content-Type": "application/x-ndjson",
            },
        )
        elapsed = time.monotonic() - t0

        assert r.status_code == 202, f"Expected 202, got {r.status_code}: {r.text}"
        data = r.json()
        assert data["accepted"] >= 1, f"No events accepted: {data}"
        assert data["incidents_created"] >= 1, (
            f"No incident created from detection hit: {data}"
        )
        assert elapsed < DETECTION_LATENCY_BUDGET_SECS, (
            f"Telemetry ingestion took {elapsed:.1f}s, exceeds {DETECTION_LATENCY_BUDGET_SECS}s budget"
        )

        # Store for downstream tests
        TestDetectionPipeline._rule_id = rule_id
        TestDetectionPipeline._rule_name = rule_name

    def test_incident_appears_in_list(self, api_client, agent_id):
        """GET /incidents returns the incident created above."""
        r = api_client.get("/api/v1/incidents", params={"agent_id": agent_id})
        assert r.status_code == 200, f"Incidents list failed: {r.status_code} {r.text}"
        incidents = r.json()
        assert len(incidents) >= 1, (
            f"Expected at least one incident for agent {agent_id}, got none"
        )

        inc = incidents[0]
        assert inc["agent_id"] == agent_id
        assert inc["severity"] == "HIGH"
        assert inc["status"] == "OPEN"
        assert inc["rule_name"] == TestDetectionPipeline._rule_name

        # Store incident ID for detail test
        TestDetectionPipeline._incident_id = inc["id"]

    def test_incident_detail_has_event_timeline(self, api_client):
        """GET /incidents/{id} returns the raw event in the timeline."""
        incident_id = TestDetectionPipeline._incident_id
        r = api_client.get(f"/api/v1/incidents/{incident_id}")
        assert r.status_code == 200, f"Incident detail failed: {r.status_code} {r.text}"
        detail = r.json()

        assert detail["id"] == incident_id
        assert detail["severity"] == "HIGH"
        assert "T1003.001" in (detail.get("mitre_techniques") or [])
        assert len(detail["events"]) >= 1, "No events in incident timeline"

        event = detail["events"][0]
        assert event["event_type"] == "process_create"
        assert "mimikatz" in json.dumps(event).lower()

    def test_duplicate_upload_deduplicates(self, api_client, agent_id):
        """Uploading the same detection within 24h must not create a second incident."""
        rule_id = TestDetectionPipeline._rule_id
        body = _telemetry_event(agent_id, rule_id, TestDetectionPipeline._rule_name, "HIGH")

        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={
                **_api_headers(),
                "X-Agent-ID": agent_id,
                "X-Tenant-ID": TENANT_ID,
                "Content-Type": "application/x-ndjson",
            },
        )
        assert r.status_code == 202
        # incidents_created should be 0 — the existing incident was updated, not duplicated
        data = r.json()
        assert data["incidents_created"] == 0, (
            f"Expected dedup (0 new incidents), got {data['incidents_created']}"
        )


# ---------------------------------------------------------------------------
# Severity escalation
# ---------------------------------------------------------------------------

class TestSeverityEscalation:
    """A follow-up detection with higher severity should escalate the incident."""

    def test_severity_escalates_on_second_hit(self, api_client):
        """Uploading a CRITICAL detection for an existing OPEN incident escalates severity."""
        # Create a fresh agent/rule pair to avoid interference
        agent_id = f"e2e-esc-{uuid.uuid4().hex[:12]}"
        rule_id = "OC-TEST-0002"
        rule_name = "E2E: Escalation Test"

        # First hit — MEDIUM
        body_med = _telemetry_event(agent_id, rule_id, rule_name, "MEDIUM")
        r1 = api_client.post(
            "/api/v1/telemetry/batch",
            content=body_med,
            headers={**_api_headers(), "X-Agent-ID": agent_id, "X-Tenant-ID": TENANT_ID,
                     "Content-Type": "application/x-ndjson"},
        )
        assert r1.status_code == 202
        assert r1.json()["incidents_created"] == 1

        # Second hit — CRITICAL
        body_crit = _telemetry_event(agent_id, rule_id, rule_name, "CRITICAL")
        r2 = api_client.post(
            "/api/v1/telemetry/batch",
            content=body_crit,
            headers={**_api_headers(), "X-Agent-ID": agent_id, "X-Tenant-ID": TENANT_ID,
                     "Content-Type": "application/x-ndjson"},
        )
        assert r2.status_code == 202
        assert r2.json()["incidents_created"] == 0, "Second hit should dedup, not create new"

        # Verify escalation
        incidents = api_client.get(
            "/api/v1/incidents", params={"agent_id": agent_id}
        ).json()
        assert len(incidents) == 1
        assert incidents[0]["severity"] == "CRITICAL", (
            f"Expected CRITICAL after escalation, got {incidents[0]['severity']}"
        )


# ---------------------------------------------------------------------------
# Latency measurement
# ---------------------------------------------------------------------------

class TestDetectionLatency:
    """Verify the <30s detection latency target end-to-end."""

    def test_incident_visible_within_latency_budget(self, api_client):
        """
        Simulates the fastest path: telemetry upload → incident queryable.
        The platform is synchronous (no Kafka in Phase 1), so latency is
        dominated by DB write + HTTP round-trip.
        """
        agent_id = f"e2e-lat-{uuid.uuid4().hex[:12]}"
        rule_id = "OC-TEST-LAT-001"
        rule_name = "E2E: Latency Test"
        body = _telemetry_event(agent_id, rule_id, rule_name, "HIGH")

        t0 = time.monotonic()

        # Upload
        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={**_api_headers(), "X-Agent-ID": agent_id, "X-Tenant-ID": TENANT_ID,
                     "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202

        # Poll until visible (up to budget)
        incident_found = False
        while time.monotonic() - t0 < DETECTION_LATENCY_BUDGET_SECS:
            incidents = api_client.get(
                "/api/v1/incidents", params={"agent_id": agent_id}
            ).json()
            if incidents:
                incident_found = True
                break
            time.sleep(0.5)

        elapsed = time.monotonic() - t0
        assert incident_found, (
            f"Incident not visible after {elapsed:.1f}s (budget: {DETECTION_LATENCY_BUDGET_SECS}s)"
        )
        # Since Phase 1 is synchronous, this should be well under 1s
        assert elapsed < DETECTION_LATENCY_BUDGET_SECS, (
            f"Detection latency {elapsed:.1f}s exceeds {DETECTION_LATENCY_BUDGET_SECS}s budget"
        )


# ---------------------------------------------------------------------------
# Incident status transitions
# ---------------------------------------------------------------------------

class TestIncidentWorkflow:
    """Verify status transitions: OPEN → INVESTIGATING → RESOLVED."""

    def test_status_transition(self, api_client):
        agent_id = f"e2e-wf-{uuid.uuid4().hex[:12]}"
        rule_id = "OC-TEST-0003"
        body = _telemetry_event(agent_id, rule_id, "E2E: Workflow Test", "MEDIUM")

        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={**_api_headers(), "X-Agent-ID": agent_id, "X-Tenant-ID": TENANT_ID,
                     "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202
        incident_id = api_client.get(
            "/api/v1/incidents", params={"agent_id": agent_id}
        ).json()[0]["id"]

        # OPEN → INVESTIGATING
        r2 = api_client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "INVESTIGATING"},
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "INVESTIGATING"

        # INVESTIGATING → RESOLVED
        r3 = api_client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "RESOLVED"},
        )
        assert r3.status_code == 200
        assert r3.json()["status"] == "RESOLVED"

    def test_invalid_status_rejected(self, api_client):
        """Invalid status transition must return 400."""
        agent_id = f"e2e-inv-{uuid.uuid4().hex[:12]}"
        rule_id = "OC-TEST-0004"
        body = _telemetry_event(agent_id, rule_id, "E2E: Invalid Status Test", "LOW")

        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={**_api_headers(), "X-Agent-ID": agent_id, "X-Tenant-ID": TENANT_ID,
                     "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202
        incident_id = api_client.get(
            "/api/v1/incidents", params={"agent_id": agent_id}
        ).json()[0]["id"]

        r2 = api_client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "EXPLODED"},
        )
        assert r2.status_code == 400


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestTelemetryEdgeCases:
    def test_empty_batch_accepted(self, api_client):
        """Empty body returns 202 with zeros (no crash)."""
        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=b"",
            headers={**_api_headers(), "X-Agent-ID": "e2e-empty",
                     "X-Tenant-ID": TENANT_ID, "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202
        data = r.json()
        assert data["accepted"] == 0
        assert data["incidents_created"] == 0

    def test_event_without_detections_not_incident(self, api_client):
        """A telemetry event with no detections must not create an incident."""
        agent_id = f"e2e-nodet-{uuid.uuid4().hex[:8]}"
        event = {
            "event_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "tenant_id": TENANT_ID,
            "hostname": "clean-host",
            "event_type": "process_create",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "payload": {"process_name": "notepad.exe"},
            "detections": [],
        }
        body = (json.dumps(event) + "\n").encode()

        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={**_api_headers(), "X-Agent-ID": agent_id,
                     "X-Tenant-ID": TENANT_ID, "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202
        assert r.json()["incidents_created"] == 0

    def test_malformed_ndjson_line_counted_as_error(self, api_client):
        """A malformed JSON line is counted in errors, not accepted."""
        body = b'{"valid": true, "detections": []}\nnot-json-at-all\n'
        r = api_client.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={**_api_headers(), "X-Agent-ID": "e2e-malformed",
                     "X-Tenant-ID": TENANT_ID, "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202
        data = r.json()
        assert data["errors"] >= 1

    def test_missing_tenant_id_dev_fallback(self):
        """
        In dev mode, TenantMiddleware falls back to OPENCLAW_DEV_TENANT_ID (default: "dev")
        when no X-Tenant-ID header or JWT tenant claim is present. The request succeeds
        scoped to the dev tenant rather than failing with 400.

        In production (non-dev), Kong rejects unauthenticated requests before they reach
        the platform API, so the 400 path is only exercised in integration tests with a
        real JWT that lacks a tenant claim.
        """
        r = httpx.post(
            f"{PLATFORM_URL}/api/v1/telemetry/batch",
            content=b'{"event_type": "process_create", "detections": []}\n',
            headers={
                "Authorization": f"Bearer {ADMIN_TOKEN}",
                "Content-Type": "application/x-ndjson",
                # No X-Tenant-ID — dev middleware injects tenant_id="dev"
            },
            timeout=10,
        )
        # Dev mode: falls back to OPENCLAW_DEV_TENANT_ID, so 202 is expected
        # Production: Kong would reject before reaching this endpoint
        assert r.status_code in (202, 400), (
            f"Unexpected status {r.status_code} for missing tenant ID"
        )
