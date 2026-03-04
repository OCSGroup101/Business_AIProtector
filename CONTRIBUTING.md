# Contributing to OpenClaw

Thank you for your interest in contributing to OpenClaw! This project is maintained by **Omni Cyber Solutions LLC** and the open-source community.

## Code of Conduct

This project adheres to our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards.

## How to Contribute

### Reporting Issues

- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md). **Do not open public issues for vulnerabilities.**
- **Bugs**: Open an issue with the `bug` label. Include OS, agent version, and reproduction steps.
- **Feature requests**: Open an issue with the `enhancement` label.

### Development Setup

#### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.77+ | Agent development |
| Python | 3.12+ | Platform API |
| Node.js | 20 LTS | Management console |
| Docker + Compose | 24+ | Dev stack |
| minisign | 0.11+ | Binary signing |

#### Quick Start

```bash
# Clone the repository
git clone https://github.com/omni-cyber-solutions/openclaw.git
cd openclaw

# Start the development stack
make dev-up

# Build the agent (host platform only)
make agent-build

# Run platform tests
make test-platform

# Run agent tests
make test-agent
```

### Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/short-description` | `feat/etw-process-collector` |
| Bug fix | `fix/issue-description` | `fix/enrollment-token-expiry` |
| Detection rule | `rule/technique-id` | `rule/T1059-001-ps-spawn` |
| Documentation | `docs/topic` | `docs/architecture-update` |

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(agent): add ETW process collector for Windows

Implements real-time process creation/termination events via ETW
provider {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}.

Closes #42
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

### Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Ensure all CI stages pass (see [CI/CD Pipeline](ARCHITECTURE.md#cicd-pipeline)).
3. Add tests for new functionality (platform: ≥80% coverage; agent: criterion benchmarks).
4. Update relevant documentation.
5. Submit PR against `main`. PRs require at least 2 approvals.
6. Security-sensitive changes require a security team review.

### Detection Rule Contributions

Rules live in `intelligence/rule-packs/`. See [Rule Development Kit](sdk/rule-development-kit/README.md) for:
- TOML rule schema reference
- Local test harness usage
- MITRE ATT&CK mapping guidelines
- False positive rate requirements (must be <0.1% in test dataset)

### Performance Requirements

Agent contributions must not degrade the performance budget:

| Component | CPU | RAM |
|-----------|-----|-----|
| Total agent | <4.0% | <80 MB |

Run `make bench-agent` to verify.

## Code Style

### Rust
- `cargo fmt` (enforced in CI)
- `cargo clippy -- -D warnings` (enforced in CI)
- No `unsafe` blocks without documented justification and security review

### Python
- `ruff` formatting (enforced in CI)
- `mypy --strict` type checking (enforced in CI)
- Docstrings required for all public functions

### TypeScript
- ESLint with project config (enforced in CI)
- `tsc --noEmit` (enforced in CI)

## License

By contributing, you agree your contributions are licensed under the [Apache License 2.0](LICENSE).
