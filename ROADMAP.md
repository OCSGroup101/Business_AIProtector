# OpenClaw Roadmap

## Phase 0 — Foundation (Weeks 1–4)

**Goal**: Working development environment with CI/CD pipeline.

- [x] Repository skeleton with all directories
- [x] Documentation (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, ARCHITECTURE, ROADMAP, LICENSE)
- [ ] Rust workspace with `tracing` logging and config loading
- [ ] FastAPI skeleton with health endpoint, Alembic baseline, Keycloak integration
- [ ] Next.js skeleton with auth flow
- [ ] `docker-compose.yml` dev stack (PG16, Redis7, Kafka3.8, Keycloak26, MinIO, Kong3.8)
- [ ] GitHub Actions CI pipeline (all 9 stages including Gitleaks, cargo-audit, cargo clippy)
- [ ] Agent cross-compilation pipeline (4 targets: Windows/Linux x86_64, Linux aarch64, macOS x86_64)
- [ ] minisign signing setup in CI

## Phase 1 — Agent Core + Platform Alpha (Weeks 5–16)

**Goal**: First real detection visible in the browser console.

### Agent
- [ ] ProcessCollector — ETW on Windows (provider `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`)
- [ ] FilesystemCollector — `ReadDirectoryChangesW` on Windows
- [ ] NetworkCollector — `WSAEventSelect` + DNS capture
- [ ] Detection engine — IOC matching with LMDB + TOML rule loader
- [ ] Containment — `terminate_process` + `quarantine_file`
- [ ] Full mTLS enrollment, heartbeat (60s), telemetry upload, SQLite ring buffer

### Platform
- [ ] Multi-tenant PostgreSQL schema + RLS
- [ ] Enrollment, heartbeat, telemetry APIs
- [ ] Agent management console (basic)
- [ ] Incident view (basic)

### Intelligence
- [ ] MalwareBazaar + URLHaus ingest pipeline
- [ ] 20 of 40 Phase 1 detection rules (execution + persistence focus)

### Testing
- [ ] `criterion` benchmarks with CPU/RAM gates
- [ ] Multi-tenant isolation test suite

## Phase 2 — Full Collector Coverage + Intelligence Platform (Weeks 17–28)

**Goal**: Production-ready for Windows endpoints.

### Agent
- [ ] PersistenceCollector (registry + scheduled tasks + services)
- [ ] AuthCollector (Windows Security event log: 4624, 4625, 4648, 4672)
- [ ] IntegrityCollector (system binary hash baseline)
- [ ] All 40 Phase 1 detection rules
- [ ] Claude API local assistant
- [ ] TTS alerts for HIGH/CRITICAL (Windows SAPI 5)
- [ ] Policy sync + signed binary updates

### Platform
- [ ] All 7 intelligence feeds
- [ ] Community IOC sharing with anonymization pipeline
- [ ] Policy management UI
- [ ] Incident management (full lifecycle)
- [ ] RBAC with 4 roles (Tenant Admin, Security Admin, Helpdesk, Auditor)
- [ ] Audit log (immutable, append-only)
- [ ] Custom STIX/TAXII feed registration

### SDK
- [ ] Rule Development Kit (TOML validator + local test harness)

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
