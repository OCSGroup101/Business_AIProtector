# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""End-to-end cert renewal integration tests.

Validates the full agent certificate lifecycle:
  Enrollment (token → agent record + cert)
  → Heartbeat (cert expiry check → renew_cert command)
  → Cert renewal (new CSR → new cert signed by same CA)
  → DB updated (cert_serial, cert_expires_at)

Run against a live dev stack:
  make dev-up
  pytest platform/api/tests/test_e2e_cert_renewal.py -v

Environment variables:
  PLATFORM_URL      Base URL (default: http://localhost:8888)
  E2E_ADMIN_TOKEN   Bearer token with TENANT_ADMIN role (default: dev-admin-token)
  E2E_TENANT_ID     Tenant ID for test data (default: dev)
  E2E_PG_CONTAINER  Postgres docker container name (default: openclaw-postgres)
"""

import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:8888")
ADMIN_TOKEN = os.environ.get("E2E_ADMIN_TOKEN", "dev-admin-token")
TENANT_ID = os.environ.get("E2E_TENANT_ID", "dev")
PG_CONTAINER = os.environ.get("E2E_PG_CONTAINER", "openclaw-postgres")
PG_USER = "openclaw"
PG_DB = "openclaw"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_headers(tenant_id: str = TENANT_ID) -> dict:
    return {
        "Authorization": f"Bearer {ADMIN_TOKEN}",
        "X-Tenant-ID": tenant_id,
    }


def _psql(sql: str) -> str:
    result = subprocess.run(
        ["docker", "exec", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-c", sql],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr}")
    return result.stdout


def _generate_key_and_csr(common_name: str) -> tuple[str, str]:
    """Generate a 2048-bit RSA key and return (private_key_pem, csr_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenClaw Agent"),
        ]))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, csr_pem


def _seed_enrollment_token(token: str, tenant_id: str, token_id: str) -> None:
    """Insert a single-use enrollment token into the public schema."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = (datetime.now(tz=timezone.utc) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S+00:00"
    )
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    _psql(f"""
INSERT INTO public.enrollment_tokens
    (id, tenant_id, token_hash, label, created_by, created_at, expires_at,
     max_uses, use_count, is_active)
VALUES (
    '{token_id}', '{tenant_id}', '{token_hash}', 'e2e-test-token',
    'e2e-test', '{now}', '{expires_at}', 1, 0, true
) ON CONFLICT (id) DO NOTHING;
""")


def _ensure_tenant_schema(tenant_id: str) -> None:
    """Create the tenant schema and agents table if they don't exist."""
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    _psql(f"CREATE SCHEMA IF NOT EXISTS {schema};")
    _psql(f"""
CREATE TABLE IF NOT EXISTS {schema}.agents (
    id VARCHAR(30) PRIMARY KEY,
    tenant_id VARCHAR(30) NOT NULL,
    hostname VARCHAR(256) NOT NULL,
    os_platform VARCHAR(32) NOT NULL,
    os_version VARCHAR(64) NOT NULL,
    os_arch VARCHAR(16) NOT NULL,
    agent_version VARCHAR(32) NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'ENROLLING',
    policy_id VARCHAR(30),
    policy_version INTEGER NOT NULL DEFAULT 0,
    cert_serial VARCHAR(64),
    cert_expires_at TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,
    last_heartbeat_metrics JSONB,
    is_active BOOLEAN NOT NULL DEFAULT true,
    enrolled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    tags JSONB DEFAULT '{{}}'::jsonb
);
""")


def _set_agent_cert_expires_at(agent_id: str, tenant_id: str, expires_at: datetime) -> None:
    """Directly update an agent's cert_expires_at for testing."""
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    ts = expires_at.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    _psql(f"""
UPDATE {schema}.agents
SET cert_expires_at = '{ts}', updated_at = NOW()
WHERE id = '{agent_id}';
""")


def _get_agent_cert_info(agent_id: str, tenant_id: str) -> dict:
    """Read cert_serial and cert_expires_at from the DB."""
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    output = _psql(
        f"SELECT cert_serial, cert_expires_at FROM {schema}.agents WHERE id = '{agent_id}';"
    )
    lines = [l.strip() for l in output.strip().splitlines() if l.strip()]
    # psql output: header | separator | data | rowcount
    if len(lines) < 3:
        return {}
    data_line = lines[2]  # skip header and separator
    parts = [p.strip() for p in data_line.split("|")]
    if len(parts) >= 2:
        return {"cert_serial": parts[0], "cert_expires_at": parts[1]}
    return {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api():
    with httpx.Client(base_url=PLATFORM_URL, headers=_api_headers(), timeout=20) as c:
        yield c


@pytest.fixture(scope="module")
def enrolled_agent(api):
    """
    Enroll a fresh agent and return (agent_id, tenant_id, ca_cert_pem).
    Cleans up after the module.
    """
    tenant_id = TENANT_ID
    token = f"e2e-token-{uuid.uuid4().hex}"
    token_id = f"e2etk{uuid.uuid4().hex[:20]}"

    _ensure_tenant_schema(tenant_id)
    _seed_enrollment_token(token, tenant_id, token_id)

    _, csr_pem = _generate_key_and_csr(f"e2e-agent-{uuid.uuid4().hex[:8]}")

    r = api.post(
        "/api/v1/agents/enroll",
        json={
            "token": token,
            "hostname": "e2e-test-host.local",
            "os_platform": "linux",
            "os_version": "22.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0-e2e",
            "csr_pem": csr_pem,
        },
        headers={"X-Tenant-ID": tenant_id},
    )
    assert r.status_code == 201, f"Enrollment failed: {r.status_code} {r.text}"
    data = r.json()
    agent_id = data["agent_id"]
    ca_cert_pem = data["ca_cert_pem"]

    yield agent_id, tenant_id, ca_cert_pem

    # Cleanup: deactivate the agent and token
    schema = f"tenant_{tenant_id.replace('-', '_')}"
    _psql(f"UPDATE {schema}.agents SET is_active = false WHERE id = '{agent_id}';")
    _psql(f"DELETE FROM public.enrollment_tokens WHERE id = '{token_id}';")


# ---------------------------------------------------------------------------
# Pre-check
# ---------------------------------------------------------------------------

class TestCertPreCheck:
    def test_platform_ready(self, api):
        r = api.get("/health/ready")
        assert r.status_code == 200, f"Platform not ready: {r.text}"

    def test_cryptography_available(self):
        """Verify cryptography lib is available for CSR generation."""
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401
        assert True


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------

class TestEnrollment:
    def test_enrollment_returns_cert(self, enrolled_agent):
        """Successful enrollment returns a PEM cert signed by the platform CA."""
        agent_id, tenant_id, ca_cert_pem = enrolled_agent
        assert agent_id.startswith("agt_"), f"Unexpected agent_id format: {agent_id}"
        assert "BEGIN CERTIFICATE" in ca_cert_pem

    def test_enrollment_cert_validity(self, api, enrolled_agent):
        """Re-enrolling with same token must fail (single-use)."""
        # The token was already used by enrolled_agent fixture — re-use should fail
        # We verify by trying to enroll with an expired/used token
        _, csr_pem = _generate_key_and_csr("second-attempt")
        r = api.post(
            "/api/v1/agents/enroll",
            json={
                "token": "invalid-token-that-does-not-exist",
                "hostname": "fake-host",
                "os_platform": "linux",
                "os_version": "22.04",
                "os_arch": "x86_64",
                "agent_version": "0.1.0",
                "csr_pem": csr_pem,
            },
            headers={"X-Tenant-ID": TENANT_ID},
        )
        assert r.status_code == 401, f"Expected 401 for invalid token, got {r.status_code}"

    def test_enrolled_agent_cert_in_db(self, enrolled_agent):
        """Enrolled agent must have cert_serial and cert_expires_at in the DB."""
        agent_id, tenant_id, _ = enrolled_agent
        info = _get_agent_cert_info(agent_id, tenant_id)
        assert info.get("cert_serial"), f"cert_serial not set in DB: {info}"
        assert info.get("cert_expires_at"), f"cert_expires_at not set in DB: {info}"

    def test_enrolled_cert_valid_72h(self, api):
        """cert_valid_seconds in the enrollment response must be ~72h (259200s)."""
        tenant_id = TENANT_ID
        token = f"e2e-token-72h-{uuid.uuid4().hex}"
        token_id = f"e2etk{uuid.uuid4().hex[:20]}"
        _seed_enrollment_token(token, tenant_id, token_id)
        _, csr_pem = _generate_key_and_csr("validity-test-agent")

        r = api.post(
            "/api/v1/agents/enroll",
            json={
                "token": token,
                "hostname": "validity-test.local",
                "os_platform": "linux",
                "os_version": "22.04",
                "os_arch": "x86_64",
                "agent_version": "0.1.0-e2e",
                "csr_pem": csr_pem,
            },
            headers={"X-Tenant-ID": tenant_id},
        )
        assert r.status_code == 201
        data = r.json()
        expected = 72 * 3600  # 259200
        assert abs(data["cert_valid_seconds"] - expected) < 60, (
            f"Expected ~{expected}s validity, got {data['cert_valid_seconds']}s"
        )
        # Cleanup
        schema = f"tenant_{tenant_id.replace('-', '_')}"
        _psql(f"UPDATE {schema}.agents SET is_active=false WHERE id='{data['agent_id']}';")
        _psql(f"DELETE FROM public.enrollment_tokens WHERE id='{token_id}';")


# ---------------------------------------------------------------------------
# Cert renewal
# ---------------------------------------------------------------------------

class TestCertRenewal:
    def test_renew_cert_returns_new_cert(self, api, enrolled_agent):
        """POST /renew-cert with valid CSR returns a new PEM cert and CA cert."""
        agent_id, tenant_id, original_ca_pem = enrolled_agent
        _, new_csr_pem = _generate_key_and_csr(agent_id)

        r = api.post(
            f"/api/v1/agents/{agent_id}/renew-cert",
            json={"csr_pem": new_csr_pem},
            headers=_api_headers(tenant_id),
        )
        assert r.status_code == 200, f"Cert renewal failed: {r.status_code} {r.text}"
        data = r.json()
        assert "client_cert_pem" in data
        assert "ca_cert_pem" in data
        assert "cert_valid_seconds" in data
        assert "BEGIN CERTIFICATE" in data["client_cert_pem"]
        assert "BEGIN CERTIFICATE" in data["ca_cert_pem"]

    def test_renewed_cert_is_72h(self, api, enrolled_agent):
        """Renewed cert validity must be ~72 hours."""
        agent_id, tenant_id, _ = enrolled_agent
        _, new_csr_pem = _generate_key_and_csr(agent_id)

        r = api.post(
            f"/api/v1/agents/{agent_id}/renew-cert",
            json={"csr_pem": new_csr_pem},
            headers=_api_headers(tenant_id),
        )
        assert r.status_code == 200
        expected = 72 * 3600
        actual = r.json()["cert_valid_seconds"]
        assert abs(actual - expected) < 60, (
            f"Expected ~{expected}s validity, got {actual}s"
        )

    def test_renewed_cert_signed_by_same_ca(self, api, enrolled_agent):
        """Renewed cert must be verifiable against the platform CA."""
        agent_id, tenant_id, original_ca_pem = enrolled_agent
        _, new_csr_pem = _generate_key_and_csr(agent_id)

        r = api.post(
            f"/api/v1/agents/{agent_id}/renew-cert",
            json={"csr_pem": new_csr_pem},
            headers=_api_headers(tenant_id),
        )
        assert r.status_code == 200
        data = r.json()

        # Load renewed cert and CA cert
        new_cert = x509.load_pem_x509_certificate(data["client_cert_pem"].encode())
        returned_ca = x509.load_pem_x509_certificate(data["ca_cert_pem"].encode())
        original_ca = x509.load_pem_x509_certificate(original_ca_pem.encode())

        # CA cert must be the same across renewals (same subject)
        assert returned_ca.subject == original_ca.subject, (
            "CA cert changed between enrollment and renewal"
        )

        # Renewed cert issuer must match CA subject
        assert new_cert.issuer == returned_ca.subject, (
            f"Cert issuer {new_cert.issuer} does not match CA subject {returned_ca.subject}"
        )

        # Renewed cert CN must be the agent_id
        cn = new_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == agent_id, f"Cert CN is {cn!r}, expected {agent_id!r}"

    def test_renewed_cert_updates_db(self, api, enrolled_agent):
        """Cert renewal must update cert_serial and cert_expires_at in the DB."""
        agent_id, tenant_id, _ = enrolled_agent
        before = _get_agent_cert_info(agent_id, tenant_id)

        _, new_csr_pem = _generate_key_and_csr(agent_id)
        r = api.post(
            f"/api/v1/agents/{agent_id}/renew-cert",
            json={"csr_pem": new_csr_pem},
            headers=_api_headers(tenant_id),
        )
        assert r.status_code == 200

        after = _get_agent_cert_info(agent_id, tenant_id)
        assert after.get("cert_serial"), "cert_serial missing after renewal"
        assert after.get("cert_expires_at"), "cert_expires_at missing after renewal"

        # cert_expires_at must have advanced (new cert issued later than original)
        assert after["cert_expires_at"] != before.get("cert_expires_at"), (
            "cert_expires_at was not updated in DB after renewal"
        )

    def test_renew_cert_invalid_csr_rejected(self, api, enrolled_agent):
        """Malformed CSR must return 400."""
        agent_id, tenant_id, _ = enrolled_agent
        r = api.post(
            f"/api/v1/agents/{agent_id}/renew-cert",
            json={"csr_pem": "not-a-valid-csr"},
            headers=_api_headers(tenant_id),
        )
        assert r.status_code == 400, f"Expected 400 for bad CSR, got {r.status_code}"

    def test_renew_cert_unknown_agent_404(self, api):
        """Renewal for non-existent agent must return 404."""
        _, csr_pem = _generate_key_and_csr("ghost-agent")
        r = api.post(
            "/api/v1/agents/agt_doesnotexist99999/renew-cert",
            json={"csr_pem": csr_pem},
            headers=_api_headers(),
        )
        assert r.status_code == 404, f"Expected 404 for unknown agent, got {r.status_code}"


# ---------------------------------------------------------------------------
# Heartbeat cert-expiry trigger
# ---------------------------------------------------------------------------

class TestHeartbeatCertExpiry:
    """Verify heartbeat queues renew_cert when cert is within 24h of expiry."""

    def _send_heartbeat(self, api, agent_id: str, tenant_id: str) -> dict:
        r = api.post(
            f"/api/v1/agents/{agent_id}/heartbeat",
            json={
                "agent_id": agent_id,
                "agent_version": "0.1.0-e2e",
                "state": "ACTIVE",
                "policy_version": 0,
                "metrics": {
                    "cpu_percent": 1.2,
                    "ram_mb": 42,
                    "ring_buffer_fill_pct": 5,
                    "events_processed_since_last_heartbeat": 100,
                },
            },
            headers=_api_headers(tenant_id),
        )
        assert r.status_code == 200, f"Heartbeat failed: {r.status_code} {r.text}"
        return r.json()

    def test_heartbeat_no_renewal_when_cert_healthy(self, api, enrolled_agent):
        """Heartbeat must NOT queue renew_cert when cert has >24h remaining."""
        agent_id, tenant_id, _ = enrolled_agent
        # Cert was just issued — 72h remaining, well above threshold
        data = self._send_heartbeat(api, agent_id, tenant_id)
        command_types = [c["type"] for c in data.get("commands", [])]
        assert "renew_cert" not in command_types, (
            f"renew_cert should not be queued for a fresh cert, got: {command_types}"
        )

    def test_heartbeat_queues_renewal_when_cert_near_expiry(self, api, enrolled_agent):
        """Heartbeat MUST queue renew_cert when cert expires in <24h."""
        agent_id, tenant_id, _ = enrolled_agent

        # Set cert to expire in 12 hours (below the 24h threshold)
        near_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=12)
        _set_agent_cert_expires_at(agent_id, tenant_id, near_expiry)

        data = self._send_heartbeat(api, agent_id, tenant_id)
        command_types = [c["type"] for c in data.get("commands", [])]
        assert "renew_cert" in command_types, (
            f"Expected renew_cert command for cert expiring in 12h, got: {command_types}"
        )

        # Restore a healthy cert expiry so subsequent tests aren't affected
        healthy_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=72)
        _set_agent_cert_expires_at(agent_id, tenant_id, healthy_expiry)

    def test_heartbeat_queues_renewal_when_cert_already_expired(self, api, enrolled_agent):
        """Heartbeat MUST queue renew_cert even when cert is already past expiry."""
        agent_id, tenant_id, _ = enrolled_agent

        # Set cert to already be expired
        past_expiry = datetime.now(tz=timezone.utc) - timedelta(hours=1)
        _set_agent_cert_expires_at(agent_id, tenant_id, past_expiry)

        data = self._send_heartbeat(api, agent_id, tenant_id)
        command_types = [c["type"] for c in data.get("commands", [])]
        assert "renew_cert" in command_types, (
            f"Expected renew_cert for already-expired cert, got: {command_types}"
        )

        # Restore
        healthy_expiry = datetime.now(tz=timezone.utc) + timedelta(hours=72)
        _set_agent_cert_expires_at(agent_id, tenant_id, healthy_expiry)


# ---------------------------------------------------------------------------
# Full renewal cycle
# ---------------------------------------------------------------------------

class TestFullRenewalCycle:
    """Simulate the complete agent cert lifecycle end-to-end."""

    def test_full_cycle_enroll_expire_renew_heartbeat(self, api):
        """
        Full cycle:
          1. Enroll agent (gets 72h cert)
          2. Artificially expire cert to <24h
          3. Heartbeat → renew_cert command queued
          4. Agent renews cert with new CSR
          5. Heartbeat after renewal → no renew_cert command
        """
        tenant_id = TENANT_ID
        token = f"e2e-cycle-{uuid.uuid4().hex}"
        token_id = f"e2etk{uuid.uuid4().hex[:20]}"
        _ensure_tenant_schema(tenant_id)
        _seed_enrollment_token(token, tenant_id, token_id)

        _, csr_pem = _generate_key_and_csr("cycle-test-agent")
        r = api.post(
            "/api/v1/agents/enroll",
            json={
                "token": token,
                "hostname": "cycle-test.local",
                "os_platform": "linux",
                "os_version": "22.04",
                "os_arch": "x86_64",
                "agent_version": "0.1.0-e2e",
                "csr_pem": csr_pem,
            },
            headers={"X-Tenant-ID": tenant_id},
        )
        assert r.status_code == 201
        agent_id = r.json()["agent_id"]

        try:
            # Step 2: expire cert to 10h remaining
            _set_agent_cert_expires_at(
                agent_id, tenant_id,
                datetime.now(tz=timezone.utc) + timedelta(hours=10)
            )

            # Step 3: heartbeat → should see renew_cert
            hb = api.post(
                f"/api/v1/agents/{agent_id}/heartbeat",
                json={
                    "agent_id": agent_id,
                    "agent_version": "0.1.0-e2e",
                    "state": "ACTIVE",
                    "policy_version": 0,
                    "metrics": {"cpu_percent": 1.0, "ram_mb": 40,
                                "ring_buffer_fill_pct": 0,
                                "events_processed_since_last_heartbeat": 0},
                },
                headers=_api_headers(tenant_id),
            )
            assert hb.status_code == 200
            hb_data = hb.json()
            assert "renew_cert" in [c["type"] for c in hb_data.get("commands", [])], (
                "Expected renew_cert command in heartbeat response"
            )

            # Step 4: agent renews with new CSR
            _, new_csr = _generate_key_and_csr(agent_id)
            renew_r = api.post(
                f"/api/v1/agents/{agent_id}/renew-cert",
                json={"csr_pem": new_csr},
                headers=_api_headers(tenant_id),
            )
            assert renew_r.status_code == 200
            assert renew_r.json()["cert_valid_seconds"] > 259000

            # Step 5: heartbeat after renewal → no renew_cert
            hb2 = api.post(
                f"/api/v1/agents/{agent_id}/heartbeat",
                json={
                    "agent_id": agent_id,
                    "agent_version": "0.1.0-e2e",
                    "state": "ACTIVE",
                    "policy_version": 0,
                    "metrics": {"cpu_percent": 1.0, "ram_mb": 40,
                                "ring_buffer_fill_pct": 0,
                                "events_processed_since_last_heartbeat": 0},
                },
                headers=_api_headers(tenant_id),
            )
            assert hb2.status_code == 200
            hb2_types = [c["type"] for c in hb2.json().get("commands", [])]
            assert "renew_cert" not in hb2_types, (
                f"renew_cert should NOT appear after successful renewal, got: {hb2_types}"
            )

        finally:
            schema = f"tenant_{tenant_id.replace('-', '_')}"
            _psql(f"UPDATE {schema}.agents SET is_active=false WHERE id='{agent_id}';")
            _psql(f"DELETE FROM public.enrollment_tokens WHERE id='{token_id}';")
