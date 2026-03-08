# OpenClaw Roadmap

## Phase 0 — Foundation (Weeks 1–4)

**Goal**: Working development environment with CI/CD pipeline.

- [x] Repository skeleton with all directories
- [x] Documentation (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, ARCHITECTURE, ROADMAP, LICENSE)
- [x] Rust workspace with `tracing` logging and config loading
- [x] FastAPI skeleton with health endpoint, Alembic baseline, Keycloak integration
- [x] Next.js skeleton with auth flow
- [x] `docker-compose.yml` dev stack (PG16, Redis7, Kafka3.8, Keycloak26, MinIO, Kong3.8)
- [x] GitHub Actions CI pipeline (all 9 stages including Gitleaks, cargo-audit, cargo clippy)
- [x] Agent cross-compilation pipeline (4 targets: Windows/Linux x86_64, Linux aarch64, macOS x86_64)
- [x] minisign signing setup in CI

## Phase 1 — Agent Core + Platform Alpha (Weeks 5–16)

**Goal**: First real detection visible in the browser console.

### Agent
- [x] ProcessCollector — ETW on Windows (provider `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`)
- [x] FilesystemCollector — `ReadDirectoryChangesW` on Windows
- [x] NetworkCollector — `WSAEventSelect` + DNS capture
- [x] Detection engine — IOC matching with LMDB + TOML rule loader
- [x] Containment — `terminate_process` + `quarantine_file`
- [x] Full mTLS enrollment, heartbeat (60s), telemetry upload, SQLite ring buffer

### Platform
- [x] Multi-tenant PostgreSQL schema + RLS
- [x] Enrollment, heartbeat, telemetry APIs
- [x] Agent management console (basic)
- [x] Incident view (basic)

### Intelligence
- [x] MalwareBazaar + URLHaus ingest pipeline
- [x] 20 of 40 Phase 1 detection rules (execution + persistence focus)

### Testing
- [x] `criterion` benchmarks with CPU/RAM gates
- [x] Multi-tenant isolation test suite

## Phase 2 — Full Collector Coverage + Intelligence Platform (Weeks 17–28)

**Goal**: Production-ready for Windows endpoints.

### Agent
- [x] PersistenceCollector (registry + scheduled tasks + services)
- [x] AuthCollector (Windows Security event log: 4624, 4625, 4648, 4672)
- [x] IntegrityCollector (system binary hash baseline)
- [x] All 40 Phase 1 detection rules + 48 total covering 12 MITRE tactics
- [x] Claude API local assistant
- [x] TTS alerts for HIGH/CRITICAL (Windows SAPI 5)
- [x] Policy sync + signed binary updates

### Platform
- [x] All 7 intelligence feeds
- [x] Community IOC sharing with anonymization pipeline
- [x] Policy management UI
- [x] Incident management (full lifecycle)
- [x] RBAC with 4 roles (Tenant Admin, Security Admin, Helpdesk, Auditor)
- [x] Audit log (immutable, append-only)
- [x] Custom STIX/TAXII feed registration

### SDK
- [x] Rule Development Kit (TOML validator + local test harness)

## Phase 3 — Enterprise + macOS/Linux (Weeks 29–40)

**Goal**: Cross-platform support + enterprise integrations.

### Agent
- [x] macOS port — Endpoint Security Framework (ESF) — eslogger Approach A + FFI Approach B
- [x] Linux port — eBPF via `aya` crate — ProcessCollector + NetworkCollector
- [x] Optional whisper.cpp STT (opt-in via policy, `stt` feature flag)
- [x] macOS TTS — `say` command (wraps AVSpeechSynthesizer natively)
- [x] Linux inotify filesystem collector — cross-platform via `notify` crate

### Platform
- [x] SIEM connectors: Splunk HEC, Elasticsearch, Microsoft Sentinel
- [x] MISP bi-directional sharing — push verified IOCs back to MISP
- [x] Custom rule development (web IDE in console)
- [x] Report generation (PDF export via reportlab)
- [x] Staged update rollout with auto-rollback
- [x] Self-hosted deployment (Helm chart for RKE2)

### SDK
- [x] Integration SDK (SIEM/SOAR connector helpers) — `sdk/integration-sdk/`

## Phase 4 — AI-Enhanced Detection (Weeks 41–52)

**Goal**: Autonomous threat correlation and hunting.

- [x] LangGraph + Claude Opus correlation agent for multi-incident pattern detection
- [x] Threat hunting query interface (natural language → structured query)
- [x] Automated incident root-cause analysis (Claude-generated streaming narrative)
- [x] Endpoint risk scoring (lightweight XGBoost + heuristic fallback)
- [x] MITRE ATT&CK coverage heatmap per tenant
- [x] Adaptive sensitivity from false positive analyst feedback
- [x] Sovereign CI migration to Forgejo Actions

## Future Considerations

- Agent support for ChromeOS (Linux VM via Crostini)
- Mobile endpoint visibility (MDM integration, read-only)
- Zero-trust network access integration
- Hardware attestation (TPM 2.0) for enrollment
- FIPS 140-3 compliance mode

## Milestone Tags

| Milestone | Target |
|-----------|--------|
| `v0.1.0-alpha` | Phase 0 complete — CI green, dev stack running |
| `v0.2.0-alpha` | Phase 1 complete — first Windows detection end-to-end |
| `v1.0.0-beta` | Phase 2 complete — production-ready Windows coverage |
| `v1.1.0` | Phase 3 complete — cross-platform + enterprise |
| `v2.0.0` | Phase 4 complete — AI-enhanced detection |
