# OpenClaw Agent Team

This document describes the 11 specialized Claude Code agent personas that govern design, development, security, and community management of the OpenClaw platform.

## Agent Roster

| Agent | Persona File | Owned Domains | Decision Authority Scope |
|---|---|---|---|
| Program Manager | `.claude/agents/program-manager.md` | Roadmap, milestones, CI gates, release cuts | Sprint scope, milestone tags, merge approval |
| Product Manager | `.claude/agents/product-manager.md` | Feature specs, MITRE coverage, threat priorities | Feature inclusion, acceptance criteria, phase alignment |
| Security Architect | `.claude/agents/security-architect.md` | mTLS, Keycloak, tenant isolation, `unsafe` Rust, signing | BLOCK/APPROVE on auth/crypto/isolation; mandatory unsafe sign-off |
| Endpoint Engineering | `.claude/agents/endpoint-engineering.md` | Rust agent, ETW, LMDB, SQLite ring buffer, event bus | Agent architecture, perf budgets, async runtime |
| Detection Engineering | `.claude/agents/detection-engineering.md` | IOC/Behavioral/Lua rules, Sigma compat, rule lifecycle | Rule IDs, severity, promotion to production |
| Threat Intelligence | `.claude/agents/threat-intelligence.md` | Feed ingestion, IOC scoring, LMDB updates | Feed schedule, scoring params, IOC removal |
| Platform Engineering | `.claude/agents/platform-engineering.md` | FastAPI, asyncpg, schema-per-tenant, Kafka, Alembic | DB schema, API design, topic naming |
| DevOps & Infrastructure | `.claude/agents/devops-infrastructure.md` | CI/CD, cross-compile, K3s/RKE2, staged rollout | Pipeline gates, infra-as-code, release automation |
| Quality Assurance | `.claude/agents/quality-assurance.md` | Coverage gates, criterion benchmarks, isolation tests | QA sign-off (required for milestone cuts) |
| User Experience | `.claude/agents/user-experience.md` | Next.js console, Tailwind, TanStack Query, design system | Component design, routing, UX patterns |
| Community & Governance | `.claude/agents/community-governance.md` | Apache 2.0, CLA, CONTRIBUTING, SECURITY.md, CoC | License compliance, PR standards, disclosure process |

## Invocation Patterns

### Direct persona invocation
Prefix your request with the role name:
```
As Security Architect, review this enrollment token validation logic.
As Detection Engineering, create a behavioral rule for T1053 (Scheduled Task).
As Threat Intelligence, design the MalwareBazaar feed integration.
```

### Agent mention syntax
Use `@agent-name` to focus context (when supported by Claude Code version):
```
@security-architect — any change to auth middleware
@endpoint-engineering — Rust agent performance questions
@quality-assurance — before milestone cut decision
```

### Workflow invocation examples

| Trigger | Invoke |
|---|---|
| New detection rule proposal | Detection Engineering → Security Architect → QA |
| Performance regression | Endpoint Engineering → QA → Program Manager |
| New API endpoint | Platform Engineering → Security Architect → QA |
| Release candidate | QA sign-off → Program Manager → DevOps |
| Security disclosure | Security Architect → Program Manager |
| Contributor CLA question | Community Governance |
| Sprint planning | Program Manager → Product Manager |

## Critical Agent Interactions

**Security Architect is mandatory for:**
- Any `unsafe` Rust block
- Enrollment or mTLS changes
- Keycloak or JWT changes
- Tenant isolation code
- Cryptographic operations

**QA sign-off is mandatory for:**
- All milestone cuts
- Production rule promotion
- Any change to isolation test assertions

**Program Manager approval is mandatory for:**
- Milestone tag creation
- Phase boundary declarations
- Sprint scope changes

## Team Communication Channels

- Issues: GitHub Issues with appropriate template
- Security issues: GitHub Security Advisory (private) — never public issues
- Code of Conduct: conduct@omnicybersolutions.com

See `docs/team/collaboration-workflow.md` for detailed inter-agent handoff patterns.
