# OpenClaw — Claude Code Session Context

## Project Identity
- **Product**: OpenClaw — open-source endpoint security platform (CrowdStrike/SentinelOne replacement)
- **Org**: Omni Cyber Solutions LLC
- **License**: Apache 2.0 (required on every source file)
- **Repo**: github.com/OCSGroup101/Business_AIProtector
- **Active Phase**: Phase 4 (Weeks 41–52) — AI-Enhanced Detection
- **Current milestone**: v1.1.0 tagged — Phase 3 complete

## Tech Stack Quick Reference
| Layer | Technology |
|---|---|
| Agent | Rust 1.77+, tokio async, LMDB IOC store, SQLite ring buffer, mlua Lua 5.4 |
| Platform API | Python 3.12, FastAPI, asyncpg, PostgreSQL 16 (schema-per-tenant) |
| Console | Next.js 14, TypeScript, Tailwind CSS, TanStack Query v5 |
| Message Bus | Kafka 3.8 |
| Auth | Keycloak 26 (two realms: `openclaw-platform`, `openclaw-agents`) |
| Cache | Redis 7 |
| Object Storage | MinIO |
| API Gateway | Kong 3.8 |
| Signing | minisign Ed25519 (agents), Cosign keyless (containers) |
| Deployment | Helm chart (`helm/openclaw/`) for RKE2/K3s |

## Critical Invariants — NEVER violate these

1. **Gitleaks Stage 0 blocks all commits — no bypass ever.** No `--no-verify` flag permitted.
2. **No `unsafe` Rust without Security Architect review.** Every `unsafe` block requires a `// SAFETY:` comment and architect sign-off.
3. **Cross-tenant access returns 403 — never an empty 200.** Isolation tests assert this explicitly.
4. **Performance budget**: agent ≤4% CPU steady-state, ≤80 MB RAM.
5. **Apache 2.0 license header required on every source file.**
6. **Update verification (Ed25519 → SHA-256 → atomic rename) must never be skipped.**

## Phase Completion Status

| Phase | Milestone | Status |
|---|---|---|
| Phase 0 — Foundation | v0.1.0-alpha | COMPLETE |
| Phase 1 — Agent Core + Platform Alpha | v0.2.0-alpha | COMPLETE |
| Phase 2 — Full Collector Coverage + Intelligence | v1.0.0-beta | COMPLETE |
| Phase 3 — Enterprise + macOS/Linux | v1.1.0 | COMPLETE |
| Phase 4 — AI-Enhanced Detection | v2.0.0 | NEXT |

## Phase 4 Priorities (Weeks 41–52)
1. LangGraph + Claude Opus correlation agent for multi-incident pattern detection
2. Threat hunting query interface (natural language → structured query)
3. Automated incident root-cause analysis (Claude-generated narrative)
4. Endpoint risk scoring (lightweight XGBoost)
5. MITRE ATT&CK coverage heatmap per tenant
6. Adaptive sensitivity from false positive analyst feedback
7. Sovereign CI migration to Forgejo Actions

## Agent Team Roster

| Agent | File | Primary Domain |
|---|---|---|
| Program Manager | `.claude/agents/program-manager.md` | Roadmap, milestones, sprint planning, CI gates |
| Product Manager | `.claude/agents/product-manager.md` | Feature specs, MITRE coverage, threat model priorities |
| Security Architect | `.claude/agents/security-architect.md` | mTLS, Keycloak, tenant isolation, `unsafe` review |
| Endpoint Engineering | `.claude/agents/endpoint-engineering.md` | Rust agent, ETW, LMDB, ring buffer, AgentState machine |
| Detection Engineering | `.claude/agents/detection-engineering.md` | IOC/Behavioral/Lua rules, Sigma compat, rule lifecycle |
| Threat Intelligence | `.claude/agents/threat-intelligence.md` | Feed ingestion, IOC scoring, CISA/MalwareBazaar/OTX |
| Platform Engineering | `.claude/agents/platform-engineering.md` | FastAPI, asyncpg, schema-per-tenant, Kafka topics |
| DevOps & Infrastructure | `.claude/agents/devops-infrastructure.md` | CI/CD, cross-compile, K3s/RKE2, staged rollout |
| Quality Assurance | `.claude/agents/quality-assurance.md` | Coverage gates, criterion benchmarks, isolation tests |
| User Experience | `.claude/agents/user-experience.md` | Console design, component patterns, B2B SaaS UX |
| Community & Governance | `.claude/agents/community-governance.md` | Apache 2.0, CLA, CONTRIBUTING, SECURITY.md |

## Invocation Hints
- Address an agent directly: "As Security Architect, review this enrollment flow."
- Use `@endpoint-engineering` to focus on Rust agent work.
- Use `@security-architect` before merging any auth or crypto change.
- See `docs/team/collaboration-workflow.md` for inter-agent handoff patterns.

## Key File Paths

### Agent (Rust)
- Workspace: `agent/Cargo.toml` (members: `"."`, `"../rdk"`)
- Event bus: `agent/src/core/event_bus.rs`
- Detection engine: `agent/src/detection/engine.rs`
- Correlation engine: `agent/src/detection/correlation.rs`
- Rule loader: `agent/src/detection/rule_loader.rs`
- Collectors: `agent/src/collectors/` (process, auth, filesystem, network, persistence, integrity, ebpf, esf)
- TTS: `agent/src/voice/tts.rs` | STT: `agent/src/voice/stt.rs` (`--features stt`)
- Updater: `agent/src/platform_connector/updater.rs`
- Kafka producer: `agent/src/platform_connector/kafka_producer.rs` (`--features kafka`)
- eBPF programs: `agent/src/bpf/*.bpf.c` (compiled separately with clang -target bpf)

### Platform API (Python)
- Entry point: `platform/api/main.py`
- DB session + tenant scoping: `platform/api/database.py`
- RBAC: `platform/api/middleware/rbac.py`
- Audit emit: `platform/api/audit_service.py`
- Intel feeds: `platform/api/intel/feed_runner.py`
- Kafka: `platform/api/kafka/{producer,consumer}.py`
- SIEM connectors: `platform/api/siem/{splunk,elasticsearch,sentinel}.py`
- Reports renderer: `platform/api/reports/renderer.py`
- Container entry: `platform/api/Dockerfile.dev` (runs `uvicorn app.main:app --app-dir /`)

### Console (Next.js)
- App pages: `platform/console/src/app/`
  - Incidents: `incidents/page.tsx`, `incidents/[id]/page.tsx`
  - Policies: `policies/page.tsx`
  - Rules IDE: `rules/page.tsx`, `rules/new/page.tsx`, `rules/[id]/page.tsx`
  - Reports: `reports/page.tsx`
  - SIEM settings: `settings/siem/page.tsx`
- API client: `platform/console/src/lib/api.ts`
- Types: `platform/console/src/types/index.ts`

### Infrastructure
- Helm chart: `helm/openclaw/` (values.yaml, templates/)
- Dev stack: `docker-compose.yml` → `make dev-up` (requires `OPENCLAW_DEV_MODE=true`)
- CI pipeline: `.github/workflows/ci.yml` (9 stages + macOS universal binary + RDK + SDK + Helm lint)

### SDK
- Integration SDK: `sdk/integration-sdk/openclaw_sdk/` (`OpenClawClient`, SIEM connectors, Pydantic models)
- Rule Development Kit: `rdk/` (validate / test / lint subcommands)

### Tests
- E2E detection pipeline: `platform/api/tests/test_e2e_detection.py`
- E2E audit: `platform/api/tests/test_e2e_audit.py`
- E2E feed sync: `platform/api/tests/test_e2e_feed_sync.py`
- Multi-tenant isolation: `platform/api/tests/test_e2e_isolation.py`
- SDK tests: `sdk/integration-sdk/tests/test_client.py`

## Dev Tokens (OPENCLAW_DEV_MODE=true only)
| Token | Role | Permissions |
|---|---|---|
| `dev-admin-token` | TENANT_ADMIN | All permissions |
| `dev-security-token` | SECURITY_ADMIN | All except users:manage |
| `dev-helpdesk-token` | HELPDESK | agents/policies/incidents/audit read |
| `dev-auditor-token` | AUDITOR | agents/policies/incidents/intel/audit read |

## Alembic Migration Chain
`0001_initial` → `0002_incidents` → `0003_global_ioc_entries` → `0004_audit_logs`
→ `0005_custom_feeds` → `0006_community_ioc` → `0007_siem_connectors`
→ `0008_deployments` → `0009_reports`

## Agent Feature Flags
| Flag | Enables | Extra deps |
|---|---|---|
| `kafka` | Kafka telemetry streaming | `rdkafka` |
| `linux-ebpf` | eBPF process/network collectors | `aya`, `aya-log`, `bytes` |
| `macos-esf` | Full ESF C FFI (requires entitlement) | — |
| `stt` | Whisper.cpp speech-to-text | `whisper-rs`, `cpal` |
| `stt` (default off) | Opt-in via policy | — |

## CI Pipeline Stages
| Stage | Job(s) | Gate |
|---|---|---|
| 0 | secret-scan (Gitleaks) | Blocks all |
| 1 | quality-rust, quality-python, quality-typescript | fmt/lint/type-check |
| 2 | sast (Bandit, Semgrep, cargo-audit) | Security scan |
| 3 | test-agent, test-rdk, test-platform, test-console, test-sdk, lint-helm, build-agent-macos (matrix) | Unit tests |
| 3b | build-agent-macos-universal (lipo) | Universal binary |
| 4 | build (Linux/Windows cross + SBOM + Trivy) | Container build |
| 5 | iac-scan (Trivy config) | IaC security |
| 6 | isolation-tests (docker-compose) | Multi-tenant E2E |
| 7 | sign-containers (Cosign, main only) | Signing |
| 8 | attest-sbom (main only) | SBOM attestation |
| 9 | dast (OWASP ZAP, main push only) | DAST |

## Known Good Configuration Notes
- Keycloak 26: health check uses management port **9000** (not 8080)
- `platform-api` docker-compose dependency: `service_started` (not `service_healthy`)
- Uvicorn CMD: `uvicorn app.main:app --host 0.0.0.0 --port 8888 --app-dir /`
- `OPENCLAW_DEV_MODE=true` required for dev RBAC tokens + auto table creation
- `readiness_check` endpoint must have `response_model=None`
