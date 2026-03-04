# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (pre-release) | Yes |
| < 1.0.0 | No |

Once v1.0.0 is released, the two most recent minor versions will receive security patches.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Preferred: GitHub Private Security Advisory

Use [GitHub's private security advisory feature](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) to report vulnerabilities directly to the maintainers.

### Alternative: Email

Send a PGP-encrypted email to **security@omnicybersolutions.com**.

PGP key fingerprint: (published at keybase.io/omnicybersec — to be set up at project launch)

### What to Include

- Description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept
- Affected component (agent, platform API, console, intelligence pipeline)
- Suggested severity (Critical/High/Medium/Low)

## Response Timeline

| Action | Target |
|--------|--------|
| Initial acknowledgement | 48 hours |
| Severity assessment | 5 business days |
| Patch for Critical/High | 14 days |
| Patch for Medium/Low | 90 days |
| Public disclosure | After patch release + 7 days |

## Scope

### In Scope

- Agent binary (all platforms)
- Platform API and console
- Authentication and authorization (JWT, mTLS, Keycloak)
- Multi-tenant isolation (schema-per-tenant, RLS)
- Supply chain (binary signing, update verification)
- Intelligence ingestion pipeline
- Detection rule engine (TOML + Lua sandbox)

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream; we will track and patch)
- Social engineering attacks
- Physical security
- Denial-of-service attacks on the public demo instance

## Security Architecture

OpenClaw's security model is documented in [docs/threat-model/](docs/threat-model/). Key controls:

- **Agent updates**: Ed25519 (minisign) signature verification before any binary replacement
- **Agent-platform transport**: Mutual TLS with client certificates issued at enrollment
- **Multi-tenant isolation**: 6-layer isolation (Keycloak → Kong → PostgreSQL schema → RLS → MinIO → Kafka)
- **Secret scanning**: Gitleaks runs on every commit (Stage 0 CI, no bypass permitted)
- **Dependency auditing**: `cargo-audit` and `pip-audit` on every CI run
- **Container signing**: Cosign keyless signing on all published images

## Bug Bounty

We do not currently operate a paid bug bounty program. Responsible disclosure will be acknowledged in release notes and, with permission, in our Hall of Thanks.
