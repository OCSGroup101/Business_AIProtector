# OpenClaw Architecture

## Overview

OpenClaw is an open-source endpoint security platform providing detection, containment, and response capabilities comparable to CrowdStrike Falcon, SentinelOne, and Microsoft Defender for Endpoint. It is designed for multi-tenant deployment and operates as a SaaS platform with an on-premises option.

## Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Agent | Rust 1.77+ | No GC pauses (<5% CPU), static binary, memory-safe, `windows` crate |
| Platform API | Python 3.12 + FastAPI | Async+asyncpg, large security library ecosystem |
| Console | Next.js 14 + TypeScript + Tailwind + TanStack Query | B2B SaaS admin pattern |
| Database | PostgreSQL 16 | Schema-per-tenant with RLS |
| Message Bus | Apache Kafka 3.8 | High-volume telemetry ingestion |
| Identity | Keycloak 26 | Two realms: platform users + agent machine JWTs |
| API Gateway | Kong 3.8 | TLS termination, rate limiting, JWT validation |
| Object Storage | MinIO | Per-tenant quarantine buckets |
| Cache | Redis 7 | Session tokens, rule/policy cache, rate limiting |
| Agent local storage | SQLite + LMDB | State/history + O(1) IOC lookup |
| Rule engine | TOML + embedded Lua (mlua) | Sigma-compatible; Lua for correlation |
| Platform AI | Claude API | Alert explanations + LangGraph correlation agent |
| Voice TTS | OS-native (SAPI 5 / AVSpeech) | Zero download, mandatory for HIGH/CRITICAL alerts |
| Voice STT | whisper.cpp (opt-in) | 39 MB, off by default |
| Update signing | minisign (Ed25519) | Agent binary integrity |
| Containers | Docker + K3s / RKE2 | Dev/Prod deployment |

## Agent Architecture

### Data Flow

```
[ProcessCollector]   ──┐
[FilesystemCollector] ─┤
[NetworkCollector]   ──┤── tokio::broadcast::channel ──► [DetectionEngine]
[PersistenceCollector]─┤      (capacity: 10,000)               │
[AuthCollector]      ──┤                                ├─► TOML rule eval + Lua
[IntegrityCollector] ─┘                                ├─► LMDB IOC lookup
                                                        ├─► Behavioral heuristics
                                                        │
                                                        ▼
                                                   [DetectionResult]
                                                        │
                                           ┌────────────┼────────────┐
                                           ▼            ▼            ▼
                                     [RingBuffer]  [Containment]  [Assistant]
                                     → upload        → action       → TTS/chat
```

### Agent State Machine

```
ENROLLING → ACTIVE → ISOLATED
                ↓        ↓
            UPDATING  (loopback only)
                ↓
            ACTIVE
```

### Performance Budget (enforced in CI via criterion)

| Component | CPU | RAM |
|-----------|-----|-----|
| ProcessCollector | 0.8% | 8 MB |
| FilesystemCollector | 0.5% | 4 MB |
| NetworkCollector | 0.8% | 12 MB |
| DetectionEngine | 1.2% | 24 MB |
| IOC Store (LMDB) | 0.3% | 16 MB |
| RingBuffer + uploader | 0.4% | 8 MB |
| Assistant (idle) | 0.0% | 2 MB |
| **TOTAL** | **<4.0%** | **<80 MB** |

## Multi-Tenant Architecture

### Isolation Layers

1. **Keycloak JWT claims** — tenant_id embedded in token, validated at Kong
2. **Kong route authorization** — tenant-scoped route ACLs
3. **PostgreSQL schema** — `tenant_{id}` schema; `SET search_path` on every connection
4. **Row-Level Security** — RLS policies as defense-in-depth backup
5. **MinIO bucket ACLs** — per-tenant bucket `quarantine-{tenant_id}`
6. **Kafka topic ACLs** — per-tenant topic prefix `openclaw.{tenant_id}.*`

### RBAC Matrix

| Permission | Tenant Admin | Security Admin | Helpdesk | Auditor |
|------------|-------------|---------------|----------|---------|
| Manage agents/policies | W | R/W | R | R |
| Apply containment | W | W | - | - |
| Manage users | W | - | - | - |
| View audit logs | W | W | W | W |
| Manage intel feeds | W | W | - | - |

## Agent-Platform Communication

- **Transport**: HTTPS with mutual TLS. Client cert issued at enrollment. JWT fallback.
- **Enrollment**: One-time token → CSR challenge → mTLS cert + initial policy bundle
- **Heartbeat**: Every 60 seconds. Reports health metrics, receives policy diff + commands.
- **Telemetry**: NDJSON batch upload every 5 minutes or at 50% ring buffer fill.
- **Intel**: Agent pulls signed bundles on heartbeat command.
- **Updates**: Binary signed with minisign Ed25519. Verification before atomic replace.

## Intelligence Ingestion Pipeline

```
External feeds → [FeedFetcher] → [Normalizer] → [Deduplicator] → [Scorer] → [Signer] → [Distributor]
                                                                                            ↓
                                                                           Per-tenant IOC bundles in MinIO
                                                                           Kafka: openclaw.intel.distribution
```

### Feed Schedule

| Feed | Interval |
|------|----------|
| CISA KEV | Daily |
| MalwareBazaar | 4 hours |
| URLHaus | 2 hours |
| OTX | 4 hours |
| MISP | 1 hour |
| AbuseIPDB | 6 hours |
| MITRE ATT&CK | Weekly |

### IOC Scoring

- Base confidence: 0.60–0.95 (feed reputation weight)
- Multi-source boost: +0.10 for ≥3 corroborating sources
- Age decay: >90 days → ×0.85
- <0.50 confidence → informational only
- >0.85 confidence → auto-block eligible

## CI/CD Pipeline

| Stage | Contents |
|-------|----------|
| 0 — Secret Scan | Gitleaks (pinned digest, blocks all, no bypass) |
| 1 — Code Quality | ruff + mypy, ESLint + tsc, cargo fmt + clippy |
| 2 — SAST | Bandit + Semgrep, cargo-audit |
| 3 — Unit Tests | pytest ≥80% coverage, cargo test + criterion gates, Jest |
| 4 — Container Build + SBOM | docker build, cargo build (4 targets), trivy, syft, minisign |
| 5 — IaC Scan | trivy config (compose, K3s manifests) |
| 6 — Isolation Tests | docker compose up → pytest tests/isolation/ → down |
| 7 — Container Signing [main] | cosign sign (keyless Sigstore → org key Phase 2) |
| 8 — SBOM Attestation [main] | cosign attest |
| 9 — DAST [staging] | OWASP ZAP authenticated scan |

## Supply Chain Security

### Agent Binary Signing
```
CI: cargo build --release (4 targets: x86_64-windows, x86_64-linux, aarch64-linux, x86_64-apple-darwin)
  → cargo-audit (dependency vulns)
  → trivy (SBOM)
  → minisign sign (Ed25519, key in GitHub Actions secret → HSM in Phase 2)
  → zip: binary + .minisig + manifest.json
```

### Agent Update Verification (Rust)
1. Verify `manifest.json` Ed25519 signature against pinned platform public key
2. Verify binary SHA-256 matches manifest
3. Write to temp path → verify executable → atomic rename
4. Report update to platform → trigger OS service restart

### Staged Rollout
Canary (5%) → 24h → Early adopters (20%) → 48h → GA (75%). Auto-rollback if crash rate >1%.

## Telemetry Event Schema

See [docs/architecture/telemetry-schema.md](docs/architecture/telemetry-schema.md) for full field definitions.

Key envelope fields: `schema_version`, `event_id`, `agent_id`, `tenant_id`, `timestamp`, `collector`, `event_type`, `severity`, `hostname`, `os`, `principal`, `payload`, `detections`, `tags`.

## Detection Rule Schema

Three rule types supported in TOML:
1. **IOC Match** — hash/IP/domain lookup in LMDB store
2. **Behavioral Pattern** — field condition matching on event fields
3. **Lua Heuristic** — sliding window correlation script

See [docs/architecture/rule-schema.md](docs/architecture/rule-schema.md) for full schema.
