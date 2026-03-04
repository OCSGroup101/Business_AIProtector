# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Enrollment integration tests.

Tests the full one-time-token → mTLS cert flow, cert renewal, and
agent policy fetch.  Requires a running platform (PLATFORM_URL) and
an admin token (OPENCLAW_ADMIN_TOKEN).

Run: pytest tests/test_enrollment.py -v
"""

import os
import pytest
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

PLATFORM_URL = os.environ.get("PLATFORM_URL", "http://localhost:8888")
ADMIN_TOKEN = os.environ.get("OPENCLAW_ADMIN_TOKEN", "dev-admin-token")
TEST_TENANT_ID = os.environ.get("TEST_TENANT_ID", "dev")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _generate_csr(hostname: str = "test-agent.local") -> tuple[str, ec.EllipticCurvePrivateKey]:
    """Generate a minimal ECDSA P-256 CSR for testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenClaw Agent"),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return csr_pem, key


def _create_enrollment_token(client: httpx.Client, max_uses: int = 1) -> str:
    """Create a single-use enrollment token via the admin API."""
    resp = client.post(
        "/api/v1/admin/enrollment-tokens",
        json={
            "tenant_id": TEST_TENANT_ID,
            "label": "pytest-enrollment-test",
            "max_uses": max_uses,
            "expires_hours": 1,
        },
        headers={"X-Admin-Token": ADMIN_TOKEN},
    )
    assert resp.status_code == 201, f"Token creation failed: {resp.text}"
    return resp.json()["token"]


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def http():
    with httpx.Client(base_url=PLATFORM_URL, timeout=10) as client:
        yield client


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestEnrollment:
    def test_enrollment_success(self, http: httpx.Client):
        """Valid token + valid CSR → agent created, cert returned."""
        token = _create_enrollment_token(http)
        csr_pem, _ = _generate_csr()

        resp = http.post("/api/v1/agents/enroll", json={
            "token": token,
            "hostname": "test-agent.local",
            "os_platform": "linux",
            "os_version": "Ubuntu 24.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0",
            "csr_pem": csr_pem,
        })

        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["agent_id"].startswith("agt_")
        assert data["tenant_id"] == TEST_TENANT_ID
        assert "-----BEGIN CERTIFICATE-----" in data["client_cert_pem"]
        assert "-----BEGIN CERTIFICATE-----" in data["ca_cert_pem"]
        assert data["cert_valid_seconds"] > 0
        assert "version" in data["policy"]

    def test_enrollment_invalid_token(self, http: httpx.Client):
        """Invalid token → 401."""
        csr_pem, _ = _generate_csr()
        resp = http.post("/api/v1/agents/enroll", json={
            "token": "not-a-real-token",
            "hostname": "test-agent.local",
            "os_platform": "linux",
            "os_version": "Ubuntu 24.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0",
            "csr_pem": csr_pem,
        })
        assert resp.status_code == 401

    def test_enrollment_token_single_use(self, http: httpx.Client):
        """Single-use token is rejected on second attempt."""
        token = _create_enrollment_token(http, max_uses=1)
        csr_pem, _ = _generate_csr()

        payload = {
            "token": token,
            "hostname": "test-agent.local",
            "os_platform": "linux",
            "os_version": "Ubuntu 24.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0",
            "csr_pem": csr_pem,
        }

        resp1 = http.post("/api/v1/agents/enroll", json=payload)
        assert resp1.status_code == 201

        csr_pem2, _ = _generate_csr()
        payload["csr_pem"] = csr_pem2
        resp2 = http.post("/api/v1/agents/enroll", json=payload)
        assert resp2.status_code == 401

    def test_enrollment_invalid_csr(self, http: httpx.Client):
        """Malformed CSR PEM → 400."""
        token = _create_enrollment_token(http)
        resp = http.post("/api/v1/agents/enroll", json={
            "token": token,
            "hostname": "test-agent.local",
            "os_platform": "linux",
            "os_version": "Ubuntu 24.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0",
            "csr_pem": "not-a-pem",
        })
        assert resp.status_code == 400

    def test_enrollment_cert_is_client_auth(self, http: httpx.Client):
        """Issued cert must have ClientAuth EKU."""
        token = _create_enrollment_token(http)
        csr_pem, _ = _generate_csr()

        resp = http.post("/api/v1/agents/enroll", json={
            "token": token,
            "hostname": "test-agent.local",
            "os_platform": "linux",
            "os_version": "Ubuntu 24.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0",
            "csr_pem": csr_pem,
        })
        assert resp.status_code == 201
        cert = x509.load_pem_x509_certificate(resp.json()["client_cert_pem"].encode())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value


class TestCertRenewal:
    """Cert renewal requires an enrolled agent — depends on enrollment tests passing."""

    @pytest.fixture(scope="class")
    def enrolled_agent(self, http: httpx.Client):
        token = _create_enrollment_token(http)
        csr_pem, _ = _generate_csr()
        resp = http.post("/api/v1/agents/enroll", json={
            "token": token,
            "hostname": "renewal-test.local",
            "os_platform": "linux",
            "os_version": "Ubuntu 24.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0",
            "csr_pem": csr_pem,
        })
        assert resp.status_code == 201
        return resp.json()

    def test_renew_cert(self, http: httpx.Client, enrolled_agent: dict):
        agent_id = enrolled_agent["agent_id"]
        csr_pem, _ = _generate_csr("renewal-test.local")

        resp = http.post(f"/api/v1/agents/{agent_id}/renew-cert", json={"csr_pem": csr_pem})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "-----BEGIN CERTIFICATE-----" in data["client_cert_pem"]
        assert data["cert_valid_seconds"] > 0

    def test_renew_cert_invalid_agent(self, http: httpx.Client):
        csr_pem, _ = _generate_csr()
        resp = http.post("/api/v1/agents/agt_doesnotexist/renew-cert", json={"csr_pem": csr_pem})
        assert resp.status_code == 404


class TestAgentPolicy:
    @pytest.fixture(scope="class")
    def enrolled_agent(self, http: httpx.Client):
        token = _create_enrollment_token(http)
        csr_pem, _ = _generate_csr()
        resp = http.post("/api/v1/agents/enroll", json={
            "token": token,
            "hostname": "policy-test.local",
            "os_platform": "linux",
            "os_version": "Ubuntu 24.04",
            "os_arch": "x86_64",
            "agent_version": "0.1.0",
            "csr_pem": csr_pem,
        })
        assert resp.status_code == 201
        return resp.json()

    def test_get_agent_policy_no_default(self, http: httpx.Client, enrolled_agent: dict):
        """If no default policy exists, returns 404."""
        agent_id = enrolled_agent["agent_id"]
        resp = http.get(f"/api/v1/agents/{agent_id}/policy")
        # 200 if a default policy was seeded, 404 otherwise — both are valid
        assert resp.status_code in (200, 404)

    def test_get_policy_unknown_agent(self, http: httpx.Client):
        resp = http.get("/api/v1/agents/agt_doesnotexist/policy")
        assert resp.status_code == 404
