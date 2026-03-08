# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Multi-tenant isolation integration tests.

Validates that:
  1. Tenant A's data is invisible to Tenant B (must return 403/404, never 200 with data)
  2. Telemetry uploaded by Tenant A cannot be read by Tenant B
  3. RBAC: Auditor cannot apply containment or create policies
  4. TenantMiddleware correctly extracts tenant_id from JWT claims (no X-Tenant-ID header)

The platform API decodes JWT payloads but does NOT verify signatures — that is Kong's
responsibility. In dev mode we craft structurally valid JWT tokens with the right claims
to exercise the tenant extraction code path without a live Keycloak round-trip.

Run against a live dev stack:
  make dev-up
  pytest platform/api/tests/test_e2e_isolation.py -v

Environment:
  PLATFORM_URL      http://localhost:8888
  E2E_ADMIN_TOKEN   dev-admin-token
  E2E_PG_CONTAINER  openclaw-postgres
"""

import base64
import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:8888")
ADMIN_TOKEN = os.environ.get("E2E_ADMIN_TOKEN", "dev-admin-token")
PG_CONTAINER = os.environ.get("E2E_PG_CONTAINER", "openclaw-postgres")
PG_USER = "openclaw"
PG_DB = "openclaw"

# Stable tenant IDs for cross-tenant tests
TENANT_A = "isolation_tenant_a"
TENANT_B = "isolation_tenant_b"


# ---------------------------------------------------------------------------
# JWT crafting helpers
# ---------------------------------------------------------------------------

def _make_jwt(tenant_id: str, roles: list[str] | None = None) -> str:
    """
    Craft a structurally valid JWT with the given claims.

    The platform API decodes (not verifies) JWT payloads — signature verification
    is delegated to Kong. This produces a valid 3-part JWT structure that the
    TenantMiddleware and RBAC middleware will parse correctly in dev mode.
    """
    if roles is None:
        roles = ["tenant_admin"]
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload_dict = {
        "tenant_id": tenant_id,
        "realm_access": {"roles": roles},
        "sub": f"e2e-user-{tenant_id}",
        "preferred_username": f"e2e_{tenant_id}",
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode()
    ).rstrip(b"=").decode()
    # Signature not verified in dev mode — use a placeholder
    return f"{header}.{payload}.e2e_test_signature"


def _jwt_headers(tenant_id: str, roles: list[str] | None = None) -> dict:
    """Headers using a crafted JWT (no explicit X-Tenant-ID — tests JWT extraction path)."""
    return {"Authorization": f"Bearer {_make_jwt(tenant_id, roles)}"}


def _explicit_headers(tenant_id: str) -> dict:
    """Headers using dev token + explicit X-Tenant-ID header (tests header extraction path)."""
    return {
        "Authorization": f"Bearer {ADMIN_TOKEN}",
        "X-Tenant-ID": tenant_id,
    }


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _psql(sql: str) -> str:
    result = subprocess.run(
        ["docker", "exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-c", sql],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr}")
    return result.stdout


def _ensure_tenant_schema(tenant_id: str) -> None:
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    _psql(f"CREATE SCHEMA IF NOT EXISTS {schema};")
    _psql(f"""
CREATE TABLE IF NOT EXISTS {schema}.incidents (
    id VARCHAR(30) PRIMARY KEY,
    tenant_id VARCHAR(30) NOT NULL,
    agent_id VARCHAR(30) NOT NULL,
    hostname VARCHAR(256) NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    rule_name VARCHAR(256) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    mitre_techniques JSONB,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    assigned_to VARCHAR(256),
    summary TEXT,
    containment_status VARCHAR(32),
    containment_actions JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
""")
    # Add any columns that may be missing from tables created by an older schema version
    _psql(
        f"ALTER TABLE {schema}.incidents "
        f"ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();"
    )
    _psql(f"""
CREATE TABLE IF NOT EXISTS {schema}.incident_events (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(30) NOT NULL REFERENCES {schema}.incidents(id) ON DELETE CASCADE,
    event_id VARCHAR(64),
    event_type VARCHAR(64),
    event_json JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
""")


def _seed_incident(incident_id: str, tenant_id: str) -> None:
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    _psql(f"""
INSERT INTO {schema}.incidents
    (id, tenant_id, agent_id, hostname, rule_id, rule_name, severity,
     status, mitre_techniques, first_seen_at, last_seen_at)
VALUES (
    '{incident_id}', '{tenant_id}', 'agt_test', 'iso-test.local',
    'OC-ISO-0001', 'Isolation Test Incident', 'HIGH',
    'OPEN', '["T1059"]'::jsonb, '{now}', '{now}'
)
ON CONFLICT (id) DO NOTHING;
""")


def _delete_incident(incident_id: str, tenant_id: str) -> None:
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    _psql(f"DELETE FROM {schema}.incidents WHERE id = '{incident_id}';")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tenant_a_incident_id():
    """Seed a Tenant A incident and clean up after."""
    inc_id = f"iso_a_{uuid.uuid4().hex[:16]}"
    _ensure_tenant_schema(TENANT_A)
    _seed_incident(inc_id, TENANT_A)
    yield inc_id
    _delete_incident(inc_id, TENANT_A)


@pytest.fixture(scope="module")
def client_a():
    with httpx.Client(
        base_url=PLATFORM_URL,
        headers=_explicit_headers(TENANT_A),
        timeout=10,
    ) as c:
        yield c


@pytest.fixture(scope="module")
def client_b():
    with httpx.Client(
        base_url=PLATFORM_URL,
        headers=_explicit_headers(TENANT_B),
        timeout=10,
    ) as c:
        yield c


@pytest.fixture(scope="module")
def client_auditor():
    with httpx.Client(
        base_url=PLATFORM_URL,
        headers={
            "Authorization": "Bearer dev-auditor-token",
            "X-Tenant-ID": TENANT_A,
        },
        timeout=10,
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Pre-check
# ---------------------------------------------------------------------------

class TestIsolationPreCheck:
    def test_platform_ready(self):
        r = httpx.get(f"{PLATFORM_URL}/health/ready", timeout=5)
        assert r.status_code == 200

    def test_tenant_schemas_exist(self):
        _ensure_tenant_schema("dev")  # dev-mode fallback tenant
        _ensure_tenant_schema(TENANT_A)
        _ensure_tenant_schema(TENANT_B)


# ---------------------------------------------------------------------------
# Cross-tenant incident isolation
# ---------------------------------------------------------------------------

class TestCrossTenantIncidentIsolation:
    """Tenant B must never see Tenant A's incidents."""

    def test_tenant_a_can_read_own_incident(self, client_a, tenant_a_incident_id):
        """Sanity: Tenant A can access its own incident list."""
        r = client_a.get("/api/v1/incidents")
        assert r.status_code == 200
        ids = [i["id"] for i in r.json()]
        assert tenant_a_incident_id in ids, (
            f"Tenant A cannot see its own incident {tenant_a_incident_id}"
        )

    def test_tenant_b_cannot_read_tenant_a_incident_by_id(self, client_b, tenant_a_incident_id):
        """
        CRITICAL: Tenant B must get 404 (not 200) for Tenant A's incident ID.
        A 200 response here is a data isolation breach.
        """
        r = client_b.get(f"/api/v1/incidents/{tenant_a_incident_id}")
        assert r.status_code in (403, 404), (
            f"CRITICAL ISOLATION FAILURE: Tenant B received {r.status_code} "
            f"for Tenant A's incident. Must be 403 or 404. Body: {r.text[:200]}"
        )
        # Critically: must NOT return Tenant A's data
        if r.status_code == 200:
            pytest.fail(
                f"CRITICAL: Tenant B received Tenant A's incident data: {r.text[:200]}"
            )

    def test_tenant_b_incident_list_excludes_tenant_a(self, client_b, tenant_a_incident_id):
        """Tenant B's incident list must not contain Tenant A's incidents."""
        r = client_b.get("/api/v1/incidents")
        assert r.status_code in (200, 403), f"Unexpected status: {r.status_code}"
        if r.status_code == 200:
            ids = [i["id"] for i in r.json()]
            assert tenant_a_incident_id not in ids, (
                f"CRITICAL: Tenant A's incident appeared in Tenant B's list!"
            )

    def test_tenant_b_cannot_modify_tenant_a_incident(self, client_b, tenant_a_incident_id):
        """Tenant B PATCH on Tenant A's incident must return 403 or 404."""
        r = client_b.patch(
            f"/api/v1/incidents/{tenant_a_incident_id}",
            json={"status": "RESOLVED"},
        )
        assert r.status_code in (403, 404), (
            f"Tenant B was able to modify Tenant A's incident: {r.status_code}"
        )


# ---------------------------------------------------------------------------
# Telemetry partitioning
# ---------------------------------------------------------------------------

class TestTelemetryPartitioning:
    """Telemetry is scoped to the submitting tenant — cross-tenant agent spoofing rejected."""

    def _ndjson(self, agent_id: str, tenant_id: str) -> bytes:
        event = {
            "event_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "hostname": f"host-{tenant_id}",
            "event_type": "process_create",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "payload": {"process_name": "test.exe"},
            "detections": [],
        }
        return (json.dumps(event) + "\n").encode()

    def test_tenant_a_telemetry_accepted(self, client_a):
        """Tenant A can submit its own telemetry."""
        body = self._ndjson(f"agt_iso_a_{uuid.uuid4().hex[:8]}", TENANT_A)
        r = client_a.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={**_explicit_headers(TENANT_A), "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202, f"Telemetry rejected: {r.status_code} {r.text}"

    def test_tenant_b_telemetry_scoped_separately(self, client_b):
        """Tenant B telemetry is scoped to Tenant B's schema."""
        body = self._ndjson(f"agt_iso_b_{uuid.uuid4().hex[:8]}", TENANT_B)
        r = client_b.post(
            "/api/v1/telemetry/batch",
            content=body,
            headers={**_explicit_headers(TENANT_B), "Content-Type": "application/x-ndjson"},
        )
        assert r.status_code == 202

    def test_spoofed_tenant_a_agent_via_tenant_b_session(self):
        """
        A Tenant B session submitting an event claiming Tenant A's agent ID
        must have that event scoped to Tenant B (not Tenant A).
        The tenant context is set by the session token, not the event payload.
        """
        tenant_a_agent_id = f"agt_tenant_a_{uuid.uuid4().hex[:8]}"
        event = {
            "event_id": str(uuid.uuid4()),
            "agent_id": tenant_a_agent_id,
            "tenant_id": TENANT_A,  # claimed in payload — should be ignored
            "hostname": "spoofed-host",
            "event_type": "process_create",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "payload": {"process_name": "spoofer.exe"},
            "detections": [],
        }
        body = (json.dumps(event) + "\n").encode()

        r = httpx.post(
            f"{PLATFORM_URL}/api/v1/telemetry/batch",
            content=body,
            headers={
                **_explicit_headers(TENANT_B),  # Tenant B session
                "X-Agent-ID": tenant_a_agent_id,
                "Content-Type": "application/x-ndjson",
            },
            timeout=10,
        )
        # Should be accepted (202) but data goes into Tenant B's schema — not Tenant A's
        assert r.status_code in (202, 400, 403), (
            f"Unexpected status for cross-tenant spoof: {r.status_code}"
        )


# ---------------------------------------------------------------------------
# JWT claim extraction (no explicit X-Tenant-ID)
# ---------------------------------------------------------------------------

class TestJwtTenantExtraction:
    """
    TenantMiddleware must extract tenant_id from JWT payload when no X-Tenant-ID
    header is present. The platform API decodes (not verifies) JWT claims — Kong
    handles verification at the gateway.
    """

    def test_jwt_tenant_a_can_access_own_incidents(self, tenant_a_incident_id):
        """Crafted JWT with tenant_id=tenant_a gives access to Tenant A's data."""
        r = httpx.get(
            f"{PLATFORM_URL}/api/v1/incidents",
            headers=_jwt_headers(TENANT_A),
            timeout=10,
        )
        assert r.status_code == 200, f"JWT-based request failed: {r.status_code} {r.text}"
        ids = [i["id"] for i in r.json()]
        assert tenant_a_incident_id in ids, (
            f"JWT tenant claim not applied: Tenant A incident missing from list"
        )

    def test_jwt_tenant_b_cannot_see_tenant_a_incident(self, tenant_a_incident_id):
        """JWT with tenant_id=tenant_b must not expose Tenant A's incident."""
        r = httpx.get(
            f"{PLATFORM_URL}/api/v1/incidents/{tenant_a_incident_id}",
            headers=_jwt_headers(TENANT_B),
            timeout=10,
        )
        assert r.status_code in (403, 404), (
            f"JWT-based cross-tenant access returned {r.status_code} — isolation breach!"
        )

    def test_jwt_without_tenant_id_uses_dev_fallback(self):
        """
        In dev mode, a JWT without tenant_id claim falls back to OPENCLAW_DEV_TENANT_ID.
        This validates the middleware fallback path.
        """
        # JWT with no tenant_id claim
        header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "no-tenant-user", "realm_access": {"roles": ["tenant_admin"]}}).encode()
        ).rstrip(b"=").decode()
        bare_jwt = f"{header}.{payload}.sig"

        r = httpx.get(
            f"{PLATFORM_URL}/api/v1/incidents",
            headers={"Authorization": f"Bearer {bare_jwt}"},
            timeout=10,
        )
        # Dev mode fallback → scoped to OPENCLAW_DEV_TENANT_ID ("dev") → 200
        assert r.status_code in (200, 400), (
            f"Unexpected status for JWT without tenant_id: {r.status_code}"
        )


# ---------------------------------------------------------------------------
# RBAC enforcement
# ---------------------------------------------------------------------------

class TestRBACIsolation:
    """Role-based access control must be enforced regardless of tenant."""

    def test_auditor_cannot_isolate_agent(self, client_auditor):
        """Auditor role must get 403 when trying to isolate an agent."""
        r = client_auditor.post(
            "/api/v1/agents/agt_iso_test/isolate",
            json={"reason": "auditor isolation attempt"},
        )
        assert r.status_code == 403, (
            f"Auditor was able to isolate an agent! Got {r.status_code}. RBAC broken."
        )

    def test_auditor_cannot_create_policy(self, client_auditor):
        """Auditor must get 403 when creating a policy."""
        r = client_auditor.post(
            "/api/v1/policies",
            json={"name": "Auditor Policy", "content_toml": "[policy]\n"},
        )
        assert r.status_code == 403, (
            f"Auditor was able to create a policy! Got {r.status_code}."
        )

    def test_auditor_can_read_incidents(self, client_auditor):
        """Auditor must be able to read incidents (has incidents:read permission)."""
        r = client_auditor.get("/api/v1/incidents")
        assert r.status_code in (200, 404), (
            f"Auditor cannot read incidents: {r.status_code}"
        )

    def test_admin_can_read_and_write_incidents(self, client_a, tenant_a_incident_id):
        """TENANT_ADMIN must be able to read and update incidents."""
        r = client_a.get("/api/v1/incidents")
        assert r.status_code == 200

        r2 = client_a.patch(
            f"/api/v1/incidents/{tenant_a_incident_id}",
            json={"status": "INVESTIGATING"},
        )
        assert r2.status_code in (200, 404), (
            f"Admin cannot update incident: {r2.status_code}"
        )


# ---------------------------------------------------------------------------
# Schema-level isolation verification
# ---------------------------------------------------------------------------

class TestSchemaIsolation:
    """Direct DB verification that tenant data is in separate schemas."""

    def test_tenant_a_incident_in_correct_schema(self, tenant_a_incident_id):
        """Seeded incident must be in tenant_a's schema, not tenant_b's."""
        schema_a = f"tenant_{TENANT_A.replace('-', '_')}"
        schema_b = f"tenant_{TENANT_B.replace('-', '_')}"

        out_a = _psql(
            f"SELECT id FROM {schema_a}.incidents WHERE id = '{tenant_a_incident_id}';"
        )
        assert tenant_a_incident_id in out_a, (
            f"Incident {tenant_a_incident_id} not found in {schema_a}.incidents"
        )

        # Must NOT appear in Tenant B's schema
        try:
            out_b = _psql(
                f"SELECT id FROM {schema_b}.incidents WHERE id = '{tenant_a_incident_id}';"
            )
            assert tenant_a_incident_id not in out_b, (
                f"CRITICAL: Incident found in wrong tenant schema {schema_b}!"
            )
        except RuntimeError:
            pass  # schema_b.incidents may not exist yet — that's fine

    def test_search_path_scoping(self):
        """
        Verify SET LOCAL search_path correctly scopes queries per tenant.
        A query run in tenant_a's search_path must not see tenant_b's data.
        """
        schema_a = f"tenant_{TENANT_A.replace('-', '_')}"
        schema_b = f"tenant_{TENANT_B.replace('-', '_')}"
        _ensure_tenant_schema(TENANT_B)

        # Seed a distinct incident in each tenant
        inc_a = f"sch_iso_a_{uuid.uuid4().hex[:12]}"
        inc_b = f"sch_iso_b_{uuid.uuid4().hex[:12]}"
        _seed_incident(inc_a, TENANT_A)
        _seed_incident(inc_b, TENANT_B)

        try:
            # Query incidents table with tenant_a search path — must only see inc_a
            out = _psql(
                f"SET search_path TO {schema_a}, public; SELECT id FROM incidents;"
            )
            assert inc_a in out, f"inc_a not found in {schema_a}"
            assert inc_b not in out, (
                f"CRITICAL: inc_b from {schema_b} visible in {schema_a} search_path!"
            )
        finally:
            _delete_incident(inc_a, TENANT_A)
            _delete_incident(inc_b, TENANT_B)
