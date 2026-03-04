# OpenClaw — Claude Code Session Context

## Project Identity
- **Product**: OpenClaw — open-source endpoint security platform (CrowdStrike/SentinelOne replacement)
- **Org**: Omni Cyber Solutions LLC
- **License**: Apache 2.0 (required on every source file)
- **Repo**: github.com/omni-cyber-solutions/openclaw
- **Active Phase**: Phase 1 (Weeks 5–16) — Core telemetry, enrollment, IOC detection

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
| Signing | minisign Ed25519 (agents), Cosign keyless (containers, Phase 1) |

## Critical Invariants — NEVER violate these

1. **Gitleaks Stage 0 blocks all commits — no bypass ever.** No `--no-verify` flag permitted.
2. **No `unsafe` Rust without Security Architect review.** Every `unsafe` block requires a `// SAFETY:` comment and architect sign-off.
3. **Cross-tenant access returns 403 — never an empty 200.** Isolation tests assert this explicitly.
4. **Performance budget**: agent ≤4% CPU steady-state, ≤80 MB RAM.
5. **Apache 2.0 license header required on every source file.**
6. **Update verification (Ed25519 → SHA-256 → atomic rename) must never be skipped.**

## Phase 1 Sprint Priorities
1. ETW ProcessCollector (Windows) — `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`
2. FastAPI enrollment API + agent mTLS cert issuance
3. LMDB IOC detection + MalwareBazaar feed integration
4. First incident visible in console (<30 s detection latency target)
5. 40 detection rules covering 12 MITRE ATT&CK tactics

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
- Agent workspace: `agent/Cargo.toml`, `agent/src/`
- Event bus: `agent/src/core/event_bus.rs`
- Detection engine: `agent/src/detection/engine.rs`
- Platform API: `platform/api/main.py`, `platform/api/database.py`
- Tenant isolation tests: `platform/api/tests/isolation/test_tenant_isolation.py`
- CI pipeline: `.github/workflows/ci.yml`
- Dev stack: `docker-compose.yml` → `make dev-up`
