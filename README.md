# OpenClaw

**The next generation of endpoint detection and response — built on agentic AI, not vendor lock-in.**

OpenClaw replaces legacy EDR platforms with an autonomous, AI-native security agent that operates directly on your endpoints and network control points. It does what a world-class cybersecurity analyst would do — continuously, at machine speed, across every device in your organisation — without the six-figure vendor contracts, opaque pricing models, or proprietary black boxes that have defined the industry for the past decade.

Apache 2.0 licensed. Free forever.

---

## The Problem with Legacy EDR

CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, and their peers represent a generation of security tooling built for the threat landscape of 2014. They are rule engines with dashboards bolted on. They detect known-bad signatures and surface alerts for a human analyst to triage. That model has three fundamental problems:

**Cost and lock-in.** Enterprise EDR contracts routinely exceed $30–80 per endpoint per year, scale poorly with organisational growth, and embed deep integrations that make switching prohibitively expensive. Vendors exploit this dependency to raise prices and bundle adjacent products. Security teams become captive customers.

**Analyst dependency at scale.** Even the best EDR generates thousands of alerts per day. Without a team of experienced analysts to triage, correlate, and respond, those alerts become noise. Most organisations cannot hire or retain the security talent needed to realise the value they are paying for. The platform does not think — it flags. Thinking is delegated to humans who are expensive, inconsistent, and unavailable at 3 AM.

**Opacity and inflexibility.** Detection logic in commercial EDR is a black box. You cannot inspect it, customise it, or understand why it fired. When a vendor's logic misses a novel attack chain, you have no recourse. When their platform has an outage — as CrowdStrike demonstrated catastrophically in July 2024 — your security posture collapses with it.

---

## The OpenClaw Approach

OpenClaw treats every endpoint as the deployment site for a specialised, autonomous security agent — one that embodies the knowledge and reasoning of an expert threat hunter, incident responder, and security engineer, operating continuously without fatigue or staffing constraints.

### Agentic AI, not alert engines

The OpenClaw agent does not simply detect and alert. It reasons. When it observes a process chain, network connection pattern, or file system event, it evaluates that observation against a live threat intelligence picture, applies contextual behavioural rules, and makes a decision about whether to alert, contain, or escalate — and why. The embedded Claude AI layer explains every action in plain language, provides remediation guidance, and can be queried directly by your team.

This is the difference between a smoke detector and a fire marshal. Legacy EDR sounds an alarm. OpenClaw investigates, contains the threat, and tells you exactly what happened.

### True autonomy at network control points

The agent is only one deployment surface. OpenClaw is designed to operate at every network control point — gateway, proxy, DNS resolver, cloud workload — as a coordinated mesh of specialised AI agents that share threat context in real time. A phishing link blocked at the perimeter automatically enriches the IOC store used by every endpoint agent in your organisation within minutes. Containment decisions made at one node propagate to the others without human coordination.

### Open by design

Every detection rule is a readable TOML file. Every scoring algorithm is documented and auditable. The full platform — agent, API, console, intelligence pipeline, and CI/CD — is published under Apache 2.0. You deploy it, you own it, you modify it. There is no call home, no telemetry exfiltration to a vendor, no licence key that stops working if you miss a renewal.

The security of your organisation should not be a proprietary secret.

---

## What OpenClaw Delivers

| Capability | Legacy EDR | OpenClaw |
|---|---|---|
| Detection logic | Vendor black box | Open TOML rules + Lua heuristics, fully auditable |
| Alert triage | Human analyst required | AI agent explains, prioritises, and recommends action |
| Incident response | Alert → ticket → analyst | Autonomous containment + plain-language narrative |
| Threat intelligence | Proprietary feed (extra cost) | 7 open feeds (CISA KEV, MalwareBazaar, OTX, MISP, URLHaus, AbuseIPDB, MITRE) |
| Cross-endpoint correlation | Available in enterprise tier | Built-in, shared IOC mesh across all enrolled endpoints |
| Cost at 1,000 endpoints | ~$40,000–80,000/year | Infrastructure only (~$200/month self-hosted) |
| Vendor dependency | Contract, renewal, feature gating | None — Apache 2.0, self-hosted, fork freely |
| Custom rules | Limited or unavailable | Full rule authoring: TOML + Lua, local test harness included |
| Multi-tenant | Expensive add-on | Native schema-per-tenant architecture |
| Agent resource footprint | 5–15% CPU, 150–400 MB RAM | <4% CPU, <80 MB RAM (enforced in CI) |

---

## Architecture

OpenClaw is three components that work together:

```
┌─────────────────────────────────────────────────────────┐
│  Endpoint / Network Control Point                        │
│                                                          │
│  openclaw-agent (Rust)                                   │
│  ├── Collectors: Process, File, Network, Auth, Integrity │
│  ├── Detection Engine: IOC (LMDB) + Behavioral + Lua     │
│  ├── Alert Uploader: fast-path to platform               │
│  ├── Intel Receiver: live IOC bundle sync                │
│  └── AI Assistant: Claude-powered triage + guidance      │
└─────────────────────┬───────────────────────────────────┘
                      │ mTLS
┌─────────────────────▼───────────────────────────────────┐
│  Platform API (Python / FastAPI)                         │
│  ├── Enrollment: CSR → mTLS cert, one-time token         │
│  ├── Telemetry: NDJSON ingest → incident service         │
│  ├── Incident Service: dedup, timeline, containment log  │
│  ├── Intel Pipeline: 7 feeds → scoring → NDJSON bundle   │
│  └── Multi-tenant: schema-per-tenant PG16 + RLS          │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│  Console (Next.js 14 / TypeScript / Tailwind)            │
│  ├── Incidents: severity, MITRE tags, timeline, workflow │
│  ├── Agents: state, heartbeat, OS, version               │
│  └── Intelligence: feed status, IOC management           │
└─────────────────────────────────────────────────────────┘
```

**Agent** — written in Rust for guaranteed low overhead. Uses Windows ETW for process telemetry (the same kernel interface CrowdStrike uses), LMDB for sub-millisecond IOC lookup, and an embedded Lua engine for sliding-window correlation rules. Connects to the platform over mutual TLS with a client certificate issued at enrollment.

**Platform** — Python 3.12 + FastAPI, PostgreSQL 16 with schema-per-tenant isolation, Apache Kafka for high-volume telemetry, Keycloak for identity, Kong at the API gateway. Designed to run on a single VM for small deployments or on Kubernetes for enterprise scale.

**Console** — Next.js 14 web application. Incidents, agents, intelligence feeds, containment actions. Connects to the API; no separate backend needed.

---

## Tech Stack

| Component | Technology |
|---|---|
| Agent | Rust 1.77+, tokio, LMDB, SQLite, mlua (Lua 5.4) |
| Platform API | Python 3.12, FastAPI, asyncpg, SQLAlchemy, Alembic |
| Console | Next.js 14, TypeScript, Tailwind CSS, TanStack Query |
| Database | PostgreSQL 16 (schema-per-tenant + RLS) |
| Message Bus | Apache Kafka 3.8 |
| Identity | Keycloak 26 |
| API Gateway | Kong 3.8 |
| Object Storage | MinIO |
| Cache | Redis 7 |
| AI | Claude API (Anthropic) |
| Agent signing | minisign Ed25519 |
| Container signing | Sigstore cosign |

---

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Rust 1.77+ (for agent development)
- Python 3.12+ (for platform development)
- Node.js 20+ (for console development)

### Run the dev stack

```bash
git clone https://github.com/OCSGroup101/Endpoint_Protector.git
cd Endpoint_Protector

# Start the full backend (Postgres, Redis, Kafka, Keycloak, Kong, MinIO)
make dev-up

# In a second terminal — run the platform API
cd platform/api
python -m uvicorn main:app --reload --port 8000

# In a third terminal — run the console
cd console
npm install && npm run dev
```

The console is at `http://localhost:3000`. The API is at `http://localhost:8000/docs`.

### Build the agent

```bash
cd agent

# Development build (current platform)
cargo build

# Release build for Windows x86_64 (cross-compile from Linux/macOS)
cargo build --release --target x86_64-pc-windows-gnu
```

### Enroll an agent

```bash
# On the platform: create a one-time enrollment token
# (Admin API — see docs/operations/enrollment.md)

# On the endpoint
./openclaw-agent --enroll <TOKEN> --config openclaw-agent.toml

# Start monitoring
./openclaw-agent --config openclaw-agent.toml
```

---

## Detection Rules

Rules are plain TOML — readable, versionable, and testable without running the agent.

```toml
[[rules]]
id = "OC-BEH-0001"
name = "Office Document Spawning Command Shell"
enabled = true

[rules.mitre]
tactics = ["TA0002"]
techniques = ["T1059.001", "T1204.002"]

[rules.match]
type = "behavioral"
event_types = ["process_create"]

[[rules.match.conditions]]
field = "payload.parent_name"
operator = "in"
values = ["winword.exe", "excel.exe", "powerpnt.exe"]

[[rules.match.conditions]]
field = "payload.process_name"
operator = "in"
values = ["cmd.exe", "powershell.exe", "wscript.exe"]

[rules.response]
severity = "HIGH"
auto_contain = ["terminate_process"]
notify = true
```

The Phase 1 rule pack covers: execution via scripting interpreters, LSASS credential access, registry persistence, process masquerading, and phishing-delivered file hashes. Full MITRE ATT&CK coverage matrix is in [docs/intelligence/coverage.md](docs/intelligence/coverage.md).

---

## Roadmap

| Phase | Target | Status |
|---|---|---|
| 0 — Foundation | Repository, CI/CD, dev stack, documentation | Complete |
| 1 — Agent Core + Platform Alpha | ETW collection, LMDB detection, enrollment, incident pipeline, console | In progress |
| 2 — Full Coverage + Intelligence | All collectors, 40 detection rules, 7 intel feeds, policy management | Planned |
| 3 — Cross-Platform + Enterprise | macOS ESF, Linux eBPF, SIEM connectors, Helm chart | Planned |
| 4 — AI-Enhanced Detection | LangGraph correlation agent, threat hunting, autonomous root-cause analysis | Planned |

Full roadmap: [ROADMAP.md](ROADMAP.md)

---

## Multi-Tenant Security Model

OpenClaw is built for MSSPs and enterprises running multiple tenants from a single platform deployment. Isolation is enforced at six independent layers:

1. Keycloak JWT claims — `tenant_id` validated at Kong before the request reaches the API
2. Kong route ACLs — tenant-scoped route authorization
3. PostgreSQL schema isolation — `SET search_path = tenant_{id}` on every connection
4. Row-Level Security — RLS policies as defence-in-depth backup
5. MinIO bucket ACLs — quarantine files isolated per tenant
6. Kafka topic ACLs — per-tenant topic prefix

Cross-tenant data access returns 403 — never an empty 200. This is enforced in the automated isolation test suite.

---

## Security

Found a vulnerability? Please report it through [GitHub Security Advisories](https://github.com/OCSGroup101/Endpoint_Protector/security/advisories/new) rather than opening a public issue. We acknowledge within 48 hours and resolve CRITICAL findings within 14 days.

See [SECURITY.md](SECURITY.md) for our full disclosure policy.

---

## Contributing

OpenClaw is built on the principle that the collective knowledge of the global security community should be a shared resource — not a product feature list guarded by a sales team.

We welcome detection rules, platform improvements, platform connectors, documentation, and translations. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

Core contribution requirements:
- All commits must pass the Gitleaks secret scan (Stage 0 — no bypass)
- Conventional Commits format
- Two approvals required for merge to `main`
- Apache 2.0 licence header on all source files

---

## Licence

Apache License 2.0. Copyright 2026 Omni Cyber Solutions LLC.

You are free to use, modify, distribute, and deploy OpenClaw in commercial and non-commercial environments. See [LICENSE](LICENSE).
