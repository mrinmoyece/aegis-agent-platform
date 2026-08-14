.DEFAULT_GOAL := help
.PHONY: help install format format-check lint type test evals eval-behavioral eval-deterministic eval-adversarial eval-recovery eval-baseline eval-fixtures eval-meta eval-integration postgres-test integration-test docs-check manifest-check migration-check observability-check check compose-config container-check

PYTHON ?= python3

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install the package and development tools
	$(PYTHON) -m pip install -e '.[dev]'

format: ## Format Python sources and tests
	$(PYTHON) -m ruff check --fix src tests scripts
	$(PYTHON) -m ruff format src tests scripts

format-check: ## Check Python formatting
	$(PYTHON) -m ruff format --check src tests scripts

lint: ## Run static lint checks
	$(PYTHON) -m ruff check src tests scripts

type: ## Run strict type checks
	$(PYTHON) -m mypy

test: ## Run deterministic unit tests with coverage
	$(PYTHON) -m pytest --cov --cov-report=term-missing

evals: eval-behavioral eval-deterministic eval-fixtures eval-baseline ## Run all required fake-only evaluation gates

eval-behavioral: ## Preserve Layers 5 and 7-10 behavioral evaluation entrypoints
	$(PYTHON) -m pytest tests/test_gateway_eval.py tests/test_agent_evals.py tests/test_remediation_evals.py tests/test_sandbox_evals.py tests/test_memory_evals.py

eval-deterministic: ## Run the complete hermetic Layer 11 scenario catalog
	$(PYTHON) -m aegis_agent_platform.evals run --output .aegis-evals/deterministic

eval-adversarial: ## Run the deterministic adversarial safety pack
	$(PYTHON) -m aegis_agent_platform.evals run --tag adversarial --tag safety --output .aegis-evals/adversarial

eval-recovery: ## Run every deterministic recovery fault cut point
	$(PYTHON) -m aegis_agent_platform.evals run --tag recovery --tag chaos --output .aegis-evals/recovery

eval-baseline: ## Enforce the reviewed baseline and hard safety invariants
	$(PYTHON) -m aegis_agent_platform.evals compare --output .aegis-evals/baseline

eval-fixtures: ## Verify fixture provenance, digests, and secret/PII policy
	$(PYTHON) -m aegis_agent_platform.evals check-fixtures

eval-meta: ## Test evaluator determinism, scoring, gates, and redaction
	$(PYTHON) -m pytest tests/test_evaluation_platform.py

eval-integration: ## Exercise evaluation-relevant PostgreSQL, pgvector, and Redis paths
	$(PYTHON) -m pytest tests/integration/test_postgres_storage.py tests/integration/test_worker_delivery.py tests/integration/test_memory_postgres.py

postgres-test: ## Run live PostgreSQL integration tests (requires AEGIS_TEST_DATABASE_URL)
	$(PYTHON) -m pytest tests/integration

integration-test: ## Run live PostgreSQL and Redis integration tests
	$(PYTHON) -m pytest tests/integration

docs-check: ## Validate documentation links and required content
	$(PYTHON) scripts/check_docs.py

manifest-check: ## Validate repository configuration manifests
	$(PYTHON) scripts/check_manifests.py

migration-check: ## Validate ordered SQL migrations and tenant controls
	$(PYTHON) scripts/check_migrations.py

observability-check: ## Validate semantic conventions, rules, dashboards, and OTel config
	$(PYTHON) scripts/check_observability.py
	@if command -v promtool >/dev/null 2>&1; then promtool check rules deploy/prometheus/rules/*.yml; else echo "promtool unavailable; structural rule validation passed"; fi

check: format-check lint type test evals docs-check manifest-check migration-check observability-check ## Run all fast local checks

compose-config: ## Render and validate the local Compose configuration
	docker compose --env-file .env.example config --quiet

container-check: ## Build the non-root application image
	docker build --check .
	docker build --tag aegis-agent-platform:local .
