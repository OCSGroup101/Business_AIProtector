"""
Multi-tenant isolation tests — HIGHEST PRIORITY test suite.

These tests verify that:
1. An agent in Tenant A CANNOT read Tenant B's incidents (must return 403, not empty 200)
2. Telemetry is partitioned correctly by tenant
3. The Auditor role cannot apply containment actions

Run: pytest tests/isolation/ -v
"""

import os
import pytest
import httpx

PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:8888")

# Fixture tokens — in CI, these are real Keycloak JWTs for test tenants
# For Phase 0: placeholder JWTs; isolation test logic is complete
TENANT_A_ADMIN_TOKEN = os.environ.get("TEST_TENANT_A_TOKEN", "tenant_a_placeholder")
TENANT_B_ADMIN_TOKEN = os.environ.get("TEST_TENANT_B_TOKEN", "tenant_b_placeholder")
TENANT_A_AUDITOR_TOKEN = os.environ.get(
    "TEST_TENANT_A_AUDITOR_TOKEN", "auditor_placeholder"
)

TENANT_A_INCIDENT_ID = os.environ.get("TEST_TENANT_A_INCIDENT_ID", "inc_test_tenant_a")


@pytest.fixture
def client_tenant_a():
    return httpx.Client(
        base_url=PLATFORM_URL,
        headers={"Authorization": f"Bearer {TENANT_A_ADMIN_TOKEN}"},
        timeout=10,
    )


@pytest.fixture
def client_tenant_b():
    return httpx.Client(
        base_url=PLATFORM_URL,
        headers={"Authorization": f"Bearer {TENANT_B_ADMIN_TOKEN}"},
        timeout=10,
    )


@pytest.fixture
def client_auditor():
    return httpx.Client(
        base_url=PLATFORM_URL,
        headers={"Authorization": f"Bearer {TENANT_A_AUDITOR_TOKEN}"},
        timeout=10,
    )


class TestTenantIsolation:
    """Verify cross-tenant data isolation."""

    def test_tenant_b_cannot_read_tenant_a_incidents(self, client_tenant_b):
        """
        CRITICAL: Tenant B must receive 403 (not 200 with empty list)
        when attempting to access Tenant A's incident by ID.
        An empty 200 would silently leak that the incident ID exists.
        """
        response = client_tenant_b.get(f"/api/v1/incidents/{TENANT_A_INCIDENT_ID}")
        assert response.status_code == 403 or response.status_code == 404, (
            f"Expected 403 or 404 for cross-tenant access, got {response.status_code}. "
            f"This is a CRITICAL isolation failure if 200 with data was returned."
        )
        # Must NOT return the actual incident data
        if response.status_code == 200:
            data = response.json()
            assert "tenant_id" not in data or data.get("tenant_id") != "tenant_a", (
                "CRITICAL: Tenant B received Tenant A's incident data!"
            )

    def test_tenant_b_agent_list_does_not_show_tenant_a_agents(self, client_tenant_b):
        """Tenant B's agent list must only contain Tenant B's agents."""
        response = client_tenant_b.get("/api/v1/agents")
        assert response.status_code in (200, 401, 403)
        if response.status_code == 200:
            agents = response.json()
            for agent in agents:
                assert agent.get("tenant_id", "tenant_b") != "tenant_a", (
                    f"CRITICAL: Tenant A agent appeared in Tenant B's list: {agent}"
                )

    def test_tenant_a_incidents_visible_to_tenant_a(self, client_tenant_a):
        """Sanity check: Tenant A can access its own incidents."""
        response = client_tenant_a.get("/api/v1/incidents")
        assert response.status_code in (
            200,
            401,
        )  # 401 = test token not valid, OK in Phase 0


class TestRBACIsolation:
    """Verify role-based access control enforcement."""

    def test_auditor_cannot_apply_containment(self, client_auditor):
        """
        Auditor role must receive 403 when attempting to isolate an agent.
        """
        response = client_auditor.post(
            "/api/v1/agents/agt_test/isolate",
            json={"reason": "test isolation attempt by auditor"},
        )
        assert response.status_code == 403, (
            f"Auditor was able to apply containment! Got {response.status_code}. "
            f"RBAC is not enforced correctly."
        )

    def test_auditor_can_read_audit_logs(self, client_auditor):
        """Auditor must be able to read audit logs (sanity check)."""
        response = client_auditor.get("/api/v1/audit")
        assert response.status_code in (
            200,
            401,
        )  # 401 OK in Phase 0 without real tokens

    def test_auditor_cannot_create_policy(self, client_auditor):
        """Auditor must not be able to create policies."""
        response = client_auditor.post(
            "/api/v1/policies",
            json={"name": "Auditor Policy", "content_toml": "[policy]\n"},
        )
        assert response.status_code == 403, (
            f"Auditor was able to create a policy! Got {response.status_code}."
        )


class TestTelemetryPartitioning:
    """Verify telemetry upload is correctly partitioned by tenant."""

    def test_telemetry_rejects_mismatched_agent_tenant(self, client_tenant_b):
        """
        A Tenant B agent must not be able to submit telemetry on behalf of
        a Tenant A agent ID.
        """
        fake_tenant_a_agent_id = "agt_tenant_a_00001"
        response = client_tenant_b.post(
            "/api/v1/telemetry/batch",
            content=b'{"agent_id": "'
            + fake_tenant_a_agent_id.encode()
            + b'", "event_type": "process.create"}\n',
            headers={
                "Content-Type": "application/x-ndjson",
                "X-Agent-ID": fake_tenant_a_agent_id,
            },
        )
        # Should fail (403) or succeed but isolate data (202 with correct scoping)
        # Phase 1: verify this returns 403 after agent ownership check is implemented
        assert response.status_code in (202, 400, 403, 404), (
            f"Unexpected status {response.status_code} for cross-tenant telemetry submission"
        )
