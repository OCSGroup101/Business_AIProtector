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

"""
Platform PKI — CA initialization and mTLS client cert issuance.

Phase 1: self-signed dev CA stored on disk or in environment variables.
Phase 2+: integrate with Vault PKI secrets engine.

Agent client certs:
  - Validity: 72 hours
  - Auto-renew trigger: <24 hours remaining (handled by heartbeat)
  - Key usage: clientAuth (EKU)
  - Subject CN: agent_id
  - SAN: DNS:agent_id
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger(__name__)

# Module-level CA cache — initialized once at startup
_ca_key: Optional[rsa.RSAPrivateKey] = None
_ca_cert: Optional[x509.Certificate] = None

# Agent cert validity
AGENT_CERT_VALIDITY_HOURS = 72
AGENT_CERT_RENEW_BEFORE_HOURS = 24


def initialize_ca() -> None:
    """
    Load or generate the platform CA.
    Call once at application startup (lifespan hook).
    """
    global _ca_key, _ca_cert

    # Priority 1: environment variables (production / CI)
    ca_key_pem = os.environ.get("OPENCLAW_CA_KEY")
    ca_cert_pem = os.environ.get("OPENCLAW_CA_CERT")
    if ca_key_pem and ca_cert_pem:
        _ca_key = cast(
            rsa.RSAPrivateKey,
            serialization.load_pem_private_key(ca_key_pem.encode(), password=None),
        )
        _ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        logger.info("Platform CA loaded from environment variables")
        return

    # Priority 2: well-known PKI directory
    pki_dir = Path(os.environ.get("OPENCLAW_PKI_DIR", "/etc/openclaw/pki"))
    key_path = pki_dir / "ca.key"
    cert_path = pki_dir / "ca.crt"

    if key_path.exists() and cert_path.exists():
        _ca_key = cast(
            rsa.RSAPrivateKey,
            serialization.load_pem_private_key(key_path.read_bytes(), password=None),
        )
        _ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        logger.info("Platform CA loaded from %s", pki_dir)
        return

    # Priority 3: generate a self-signed dev CA
    logger.warning(
        "No CA found at %s or in env — generating ephemeral dev CA. "
        "Set OPENCLAW_CA_KEY / OPENCLAW_CA_CERT for persistent CA.",
        pki_dir,
    )
    _ca_key, _ca_cert = _generate_dev_ca()

    # Persist to disk so restarts reuse the same CA
    try:
        pki_dir.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(
            _ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(_ca_cert.public_bytes(serialization.Encoding.PEM))
        logger.info("Dev CA persisted to %s", pki_dir)
    except OSError as exc:
        logger.warning("Could not persist dev CA to disk: %s", exc)


def _generate_dev_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a 2048-bit RSA self-signed CA (dev/test only)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Omni Cyber Solutions LLC"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "OpenClaw Agent CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "OpenClaw Dev CA"),
        ]
    )

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    return key, cert


def _get_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    if _ca_key is None or _ca_cert is None:
        raise RuntimeError("PKI not initialized — call pki.initialize_ca() at startup")
    return _ca_key, _ca_cert


def sign_agent_csr(csr_pem: str, agent_id: str) -> tuple[str, str, str, datetime]:
    """
    Validate a PEM-encoded agent CSR and issue a 72-hour mTLS client certificate.

    Returns:
        client_cert_pem: PEM string
        ca_cert_pem:     PEM string
        cert_serial_hex: hex string of the certificate serial number
        cert_expires_at: UTC datetime when the cert expires
    """
    ca_key, ca_cert = _get_ca()

    # Load and validate the CSR
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as exc:
        raise ValueError(f"Invalid CSR PEM: {exc}") from exc

    if not csr.is_signature_valid:
        raise ValueError("CSR signature verification failed")

    serial = x509.random_serial_number()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=AGENT_CERT_VALIDITY_HOURS)

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenClaw Agent"),
                    x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(expires_at)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(agent_id)]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                cast(rsa.RSAPublicKey, ca_cert.public_key())
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_serial_hex = format(serial, "x")

    return client_cert_pem, ca_cert_pem, cert_serial_hex, expires_at


def get_ca_cert_pem() -> str:
    """Return the CA certificate as PEM — used by agents to pin the CA."""
    _, ca_cert = _get_ca()
    return ca_cert.public_bytes(serialization.Encoding.PEM).decode()
