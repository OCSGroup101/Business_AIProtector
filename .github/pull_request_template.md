## Linked Issue

Closes #<!-- issue number -->

## Change Type

<!-- Check all that apply -->
- [ ] Bug fix
- [ ] New feature
- [ ] Detection rule (new or update)
- [ ] Refactor (no behavior change)
- [ ] Performance improvement
- [ ] Documentation
- [ ] CI/Infrastructure
- [ ] Dependency update

## Affected Components

<!-- Check all that apply -->
- [ ] Agent (Rust)
- [ ] Platform API (FastAPI)
- [ ] Console (Next.js)
- [ ] Detection Rules
- [ ] Threat Intelligence Pipeline
- [ ] Infrastructure / CI

## Description

<!-- Briefly describe what this PR does and why -->

## Testing Evidence

<!-- Describe how you tested this change -->
- [ ] Unit tests added or updated
- [ ] Integration tests pass locally (`make test`)
- [ ] Benchmark run (if hot path affected) — paste criterion output below

```
<!-- criterion output here if applicable -->
```

## Security Review

**Required if any of the following apply — do not merge without Security Architect sign-off:**

- [ ] Contains `unsafe` Rust (requires Security Architect sign-off + `// SAFETY:` comment)
- [ ] Changes authentication or authorization logic
- [ ] Changes tenant isolation code (`search_path`, RLS, JWT validation)
- [ ] Changes cryptographic operations (signing, cert handling, key management)
- [ ] Changes enrollment or mTLS flow

Security Architect approval: <!-- @mention or "N/A — no security-sensitive changes" -->

## Checklist

- [ ] Apache 2.0 license header present on all new source files
- [ ] No secrets, credentials, or PII in code or tests
- [ ] CI all green (or explain any known failures)
- [ ] `CHANGELOG.md` updated (if user-visible change)
- [ ] Documentation updated (if behavior changed)
- [ ] CLA signed (external contributors only)
- [ ] Commit messages follow Conventional Commits format
