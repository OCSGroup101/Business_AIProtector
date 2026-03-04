# OpenClaw — Developer Makefile
# Usage: make <target>

.PHONY: help dev-up dev-down dev-logs dev-reset \
        agent-build agent-build-all agent-test bench-agent \
        test-platform test-console test-isolation \
        lint-agent lint-platform lint-console \
        sign-agent clean

SHELL := /bin/bash
PROJECT_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
AGENT_DIR    := $(PROJECT_ROOT)agent
PLATFORM_DIR := $(PROJECT_ROOT)platform/api
CONSOLE_DIR  := $(PROJECT_ROOT)platform/console

# ─── Colours ──────────────────────────────────────────────────────────────
BOLD   := \033[1m
RESET  := \033[0m
GREEN  := \033[32m
YELLOW := \033[33m
CYAN   := \033[36m

help: ## Show this help
	@echo -e "$(BOLD)OpenClaw Development Commands$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-24s$(RESET) %s\n", $$1, $$2}'

# ─── Dev Stack ────────────────────────────────────────────────────────────
dev-up: ## Start the full development stack
	@echo -e "$(GREEN)Starting OpenClaw dev stack...$(RESET)"
	@test -f .env || cp .env.example .env
	docker compose up -d
	@echo -e "$(GREEN)Dev stack ready:$(RESET)"
	@echo -e "  Console:    http://localhost:3000"
	@echo -e "  API:        http://localhost:8888"
	@echo -e "  Keycloak:   http://localhost:8080  (admin/keycloak_admin_dev)"
	@echo -e "  MinIO:      http://localhost:9001  (openclaw_minio/openclaw_minio_dev)"
	@echo -e "  Kong Admin: http://localhost:8001"

dev-down: ## Stop the development stack
	docker compose down

dev-logs: ## Tail all dev stack logs
	docker compose logs -f

dev-reset: ## Destroy and recreate dev stack (WARNING: deletes all data)
	@read -p "This will delete all dev data. Continue? [y/N] " confirm && \
		[[ $$confirm == [yY] ]] || exit 1
	docker compose down -v
	make dev-up

dev-status: ## Show health of all dev services
	docker compose ps

# ─── Agent (Rust) ─────────────────────────────────────────────────────────
agent-build: ## Build agent for host platform (debug)
	@echo -e "$(YELLOW)Building agent (debug, host platform)...$(RESET)"
	cd $(AGENT_DIR) && cargo build

agent-build-release: ## Build agent for host platform (release)
	cd $(AGENT_DIR) && cargo build --release

agent-build-all: ## Cross-compile agent for all 4 targets
	@echo -e "$(YELLOW)Cross-compiling agent (all targets)...$(RESET)"
	cd $(AGENT_DIR) && \
		cargo build --release --target x86_64-pc-windows-gnu && \
		cargo build --release --target x86_64-unknown-linux-gnu && \
		cargo build --release --target aarch64-unknown-linux-gnu && \
		cargo build --release --target x86_64-apple-darwin
	@echo -e "$(GREEN)All targets built successfully.$(RESET)"

agent-test: ## Run agent unit tests
	cd $(AGENT_DIR) && cargo test

bench-agent: ## Run agent criterion benchmarks
	@echo -e "$(YELLOW)Running agent benchmarks (CI performance gates)...$(RESET)"
	cd $(AGENT_DIR) && cargo bench

lint-agent: ## Run Rust linters (fmt + clippy)
	cd $(AGENT_DIR) && cargo fmt --check
	cd $(AGENT_DIR) && cargo clippy -- -D warnings

audit-agent: ## Run cargo-audit for dependency vulnerabilities
	cd $(AGENT_DIR) && cargo audit

sign-agent: ## Sign release binaries with minisign (requires MINISIGN_SECRET_KEY env var)
	@echo -e "$(YELLOW)Signing agent binaries...$(RESET)"
	@for target in x86_64-pc-windows-gnu x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin; do \
		binary="$(AGENT_DIR)/target/$$target/release/openclaw-agent"; \
		[ -f "$$binary" ] || binary="$$binary.exe"; \
		[ -f "$$binary" ] && minisign -S -s "$$MINISIGN_SECRET_KEY" -m "$$binary" || echo "Skipping $$target (not built)"; \
	done

# ─── Platform (Python) ────────────────────────────────────────────────────
test-platform: ## Run platform API tests (requires dev stack)
	cd $(PLATFORM_DIR) && python -m pytest tests/ -v --cov=. --cov-report=term-missing

test-isolation: ## Run multi-tenant isolation tests
	@echo -e "$(YELLOW)Running isolation tests...$(RESET)"
	docker compose up -d
	cd $(PLATFORM_DIR) && python -m pytest tests/isolation/ -v
	@echo -e "$(GREEN)Isolation tests complete.$(RESET)"

lint-platform: ## Run Python linters (ruff + mypy)
	cd $(PLATFORM_DIR) && ruff check . && ruff format --check .
	cd $(PLATFORM_DIR) && mypy . --strict

# ─── Console (TypeScript) ─────────────────────────────────────────────────
test-console: ## Run console unit tests
	cd $(CONSOLE_DIR) && npm test

lint-console: ## Run TypeScript linters (ESLint + tsc)
	cd $(CONSOLE_DIR) && npm run lint
	cd $(CONSOLE_DIR) && npx tsc --noEmit

# ─── Combined ─────────────────────────────────────────────────────────────
lint: lint-agent lint-platform lint-console ## Run all linters

test: agent-test test-platform test-console ## Run all tests

# ─── Database ─────────────────────────────────────────────────────────────
db-migrate: ## Run Alembic migrations
	cd $(PLATFORM_DIR) && alembic upgrade head

db-revision: ## Create new Alembic migration
	@read -p "Migration message: " msg && \
		cd $(PLATFORM_DIR) && alembic revision --autogenerate -m "$$msg"

# ─── Intelligence ─────────────────────────────────────────────────────────
intel-seed: ## Seed dev intelligence data (requires dev stack)
	docker compose exec platform-api python scripts/seed_intel.py

# ─── Utility ──────────────────────────────────────────────────────────────
clean: ## Remove build artifacts
	cd $(AGENT_DIR) && cargo clean
	cd $(CONSOLE_DIR) && rm -rf .next node_modules

env-example: ## Print example .env file
	@cat .env.example
