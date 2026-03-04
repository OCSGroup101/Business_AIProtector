# OpenClaw Agent Collaboration Workflows

This document defines the handoff patterns, review gates, and escalation paths for the OpenClaw agent team.

---

## 1. Detection Rule Lifecycle

New detection rule from idea to production.

```
Threat Intelligence
    │  Identifies emerging TTP or new IOC campaign
    │  Produces: TTP description + IOC samples + MITRE technique
    ▼
Detection Engineering
    │  Authors rule (YAML or Lua)
    │  Produces: rule file + test event (match) + benign event (no-match)
    │  Creates GitHub Issue using `detection_rule.yml` template
    ▼
Security Architect ──(if rule involves auth/evasion)
    │  Reviews for evasion-resistant logic
    │  Decision: APPROVE / BLOCK / CONDITIONAL
    ▼
Quality Assurance
    │  Runs test event corpus against rule engine
    │  Verifies: match fires, benign does not, perf within 5ms/event
    │  Provides: TP/FP rate estimate on staging
    ▼
Program Manager
    │  Merge approval after CI green + QA sign-off
    │  Promotes rule: staging → production via Alembic migration
    ▼
Production
```

**Rule promotion commands:**
```bash
# Detection Engineering promotes to staging
git checkout -b feat/rules/OC-BEH-0042-scheduled-task
# ... commit rule file ...
gh pr create --template detection_rule.yml

# After QA sign-off, Program Manager merges
# DevOps CI deploys to staging tenant automatically
```

---

## 2. New Feature Lifecycle

From feature request to deployed capability.

```
Product Manager
    │  Writes feature spec: user story + acceptance criteria + MITRE mapping
    │  Phase alignment confirmed, feature flag named
    ▼
Security Architect
    │  Threat model review for new capability
    │  Identifies: attack surface, isolation requirements, auth changes needed
    │  Produces: security requirements addendum to spec
    ▼
Platform Engineering / Endpoint Engineering (parallel if independent)
    │  Platform: API design, DB schema, Alembic migration
    │  Endpoint: Agent-side collection or detection changes
    │  Each produces: implementation PR with linked spec
    ▼
Quality Assurance
    │  Integration tests across both layers
    │  Tenant isolation matrix for new endpoints (see isolation test pattern)
    │  Performance impact assessment
    ▼
User Experience ──(if console-visible feature)
    │  Component implementation
    │  B2B UX review: triage workflow, loading states, empty states
    ▼
DevOps & Infrastructure
    │  Staging deployment
    │  Staged rollout plan (5% → 20% → 75% → 100%)
    ▼
Program Manager
    │  Final merge approval
    │  Milestone tag if phase-complete
```

---

## 3. Security Incident Response

When any agent identifies a potential security issue in the codebase.

```
Any Agent
    │  Detects: possible vuln (isolation leak, unsafe block, secret in code, etc.)
    │  Action: STOP current task, escalate immediately
    ▼
Security Architect (leads)
    │  Assesses severity (CRITICAL/HIGH/MEDIUM/LOW)
    │  For CRITICAL/HIGH: opens private GitHub Security Advisory immediately
    │  For external reporters: acknowledges within 48h via conduct@omnicybersolutions.com
    ▼
Program Manager (comms)
    │  Notifies affected stakeholders if public impact
    │  Manages disclosure timeline per SECURITY.md
    ▼
Responsible Agent
    │  Develops fix on private branch (never public while unpatched)
    ▼
Security Architect
    │  Reviews fix (mandatory sign-off)
    ▼
Quality Assurance
    │  Regression test: verify fix works, no new issues
    ▼
DevOps
    │  Emergency release if CRITICAL
    │  Coordinated disclosure after fix deployed
```

**Escalation contacts:**
- Security issues: GitHub Security Advisory (private)
- Conduct issues: conduct@omnicybersolutions.com

---

## 4. Performance Regression Response

When a benchmark regression is detected in CI.

```
CI Stage 6 fails: criterion regression >10%
    ▼
Endpoint Engineering
    │  Identifies: which benchmark, which commit introduced it
    │  Profiling: flamegraph or perf analysis
    │  Options: fix regression OR document why acceptable
    ▼
Quality Assurance
    │  Re-runs benchmark suite on clean hardware
    │  Confirms regression is real (not CI noise)
    ▼
Endpoint Engineering
    │  Submits fix or exception request with justification
    ▼
Program Manager
    │  Approves exception (if justified) or blocks merge until fixed
```

**Performance budget (never exceed):**
- Agent CPU: ≤4% steady-state
- Agent RAM: ≤80 MB RSS
- Event throughput: ≥10,000 events/sec
- IOC lookup P99: <1 ms

---

## 5. Dependency Update and Security Audit

Routine maintenance triggered by cargo-audit or pip-audit failures.

```
CI Stage 4 fails: CRITICAL or HIGH CVE in dependency
    ▼
DevOps & Infrastructure
    │  Identifies: affected package, CVE details, fix available?
    ▼
Security Architect
    │  Assesses: exploitability in OpenClaw context
    │  Decision: UPDATE_IMMEDIATELY / WORKAROUND / ACCEPT_RISK
    ▼
Responsible Engineering Agent (Platform or Endpoint)
    │  Updates dependency, verifies build + tests pass
    ▼
Quality Assurance
    │  Regression tests — confirm no functionality broken
    ▼
Program Manager
    │  Expedited merge (no sprint wait for CRITICAL CVEs)
```

---

## 6. Release Cut Workflow

For milestone releases (v0.1.0-alpha, etc.).

```
Program Manager
    │  Declares release candidate on `release/vX.Y.Z` branch
    ▼
Quality Assurance (sign-off checklist)
    │  □ All CI stages green on release branch
    │  □ Coverage: Python ≥80%, Rust ≥70%, TS ≥70%
    │  □ Benchmarks: within tolerance (no >10% regression)
    │  □ Isolation tests: all 403 assertions pass
    │  □ Manual smoke test on staging
    │  □ No open P0/P1 bugs
    ▼
Security Architect
    │  Final security review of release notes
    │  Confirm no unpatched CVEs in release
    ▼
DevOps & Infrastructure
    │  Tag release: `git tag vX.Y.Z && git push origin vX.Y.Z`
    │  CI auto-triggers: full pipeline → container sign → GHCR push → GitHub Release
    │  Agent binaries: signed, uploaded to MinIO releases/ bucket
    ▼
Community & Governance
    │  Publish release notes (no security detail for patched vulns)
    │  Update CHANGELOG.md
    │  Announce in community channels
```

---

## Inter-Agent Communication Conventions

### In PR descriptions
```markdown
## Agent Reviews Required
- [ ] @security-architect — auth/crypto changes present
- [ ] @quality-assurance — new endpoint needs isolation test
- [ ] @program-manager — ready for merge approval
```

### In GitHub Issues
- Tag the relevant agent persona in the issue body
- Use `detection_rule.yml` template for rule submissions
- Use `security_disclosure.yml` — never for security issues (use private advisory)

### Handoff signals
- "Pending Security Architect review" — block merge until explicit APPROVE
- "QA sign-off: PASS" — ready for Program Manager merge approval
- "BLOCK: [reason]" — hard stop, do not merge

---

## Escalation Matrix

| Situation | First Contact | Escalate To |
|---|---|---|
| `unsafe` Rust without comment | Security Architect | Program Manager (block merge) |
| 403 not returned on cross-tenant | Security Architect | QA (add test), Program Manager (block) |
| Secret detected by Gitleaks | Security Architect | DevOps (rotate immediately) |
| CVE in dependency | DevOps | Security Architect (assess) |
| CLA missing on PR | Community Governance | Program Manager (block merge) |
| Apache 2.0 header missing | Community Governance | Author (fix before merge) |
| Benchmark regression >10% | QA | Endpoint Engineering (fix or justify) |
| Coverage gate failure | QA | Responsible Engineering Agent |
