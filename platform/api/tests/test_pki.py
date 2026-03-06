# Copyright 2024 Omni Cyber Solutions LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for platform/api/pki.py — CA init and agent cert issuance."""

from datetime import timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from platform.api import pki


@pytest.fixture(autouse=True)
def reset_ca():
    """Reset the module-level CA cache between tests."""
    pki._ca_key = None
    pki._ca_cert = None
    yield
    pki._ca_key = None
    pki._ca_cert = None


class TestInitializeCa:
    def test_generates_dev_ca_when_no_env_or_files(self):
        pki.initialize_ca()
        assert pki._ca_key is not None
        assert pki._ca_cert is not None

    def test_get_ca_cert_pem_returns_pem(self):
        pki.initialize_ca()
        pem = pki.get_ca_cert_pem()
        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert "-----END CERTIFICATE-----" in pem

    def test_ca_cert_is_self_signed(self):
        pki.initialize_ca()
        cert = pki._ca_cert
        assert cert.subject == cert.issuer

    def test_ca_cert_is_ca(self):
        pki.initialize_ca()
        bc = pki._ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_get_ca_raises_before_init(self):
        with pytest.raises(RuntimeError, match="PKI not initialized"):
            pki._get_ca()

    def test_initialize_ca_from_env(self, monkeypatch):
        """CA can be loaded from OPENCLAW_CA_KEY / OPENCLAW_CA_CERT env vars."""
        pki.initialize_ca()
        key_pem = pki._ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
        cert_pem = pki.get_ca_cert_pem()

        # Reset and reload via env
        pki._ca_key = None
        pki._ca_cert = None
        monkeypatch.setenv("OPENCLAW_CA_KEY", key_pem)
        monkeypatch.setenv("OPENCLAW_CA_CERT", cert_pem)
        pki.initialize_ca()
        assert pki._ca_cert is not None
        assert isinstance(pki._ca_key, rsa.RSAPrivateKey)


class TestSignAgentCsr:
    def _make_csr(self, cn: str = "test-agent") -> str:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)]))
            .sign(key, __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM).decode()

    def test_sign_csr_returns_four_values(self):
        pki.initialize_ca()
        csr_pem = self._make_csr("agent-001")
        cert_pem, ca_pem, serial_hex, expires_at = pki.sign_agent_csr(csr_pem, "agent-001")
        assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert ca_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert len(serial_hex) > 0
        assert expires_at.tzinfo == timezone.utc

    def test_signed_cert_has_client_auth_eku(self):
        pki.initialize_ca()
        csr_pem = self._make_csr("agent-002")
        cert_pem, _, _, _ = pki.sign_agent_csr(csr_pem, "agent-002")
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_signed_cert_cn_matches_agent_id(self):
        pki.initialize_ca()
        csr_pem = self._make_csr("my-agent")
        cert_pem, _, _, _ = pki.sign_agent_csr(csr_pem, "my-agent")
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        assert cn == "my-agent"

    def test_invalid_csr_raises_value_error(self):
        pki.initialize_ca()
        with pytest.raises(ValueError, match="Invalid CSR"):
            pki.sign_agent_csr("not-a-valid-csr", "agent-x")
