.DEFAULT_GOAL := help
.PHONY: help install format format-check lint type test evals eval-behavioral eval-deterministic eval-adversarial eval-recovery eval-baseline eval-fixtures eval-meta eval-integration postgres-test integration-test docs-check manifest-check migration-check observability-check protocol-check production-check qualification-check qualification-demo qualification-chaos qualification-load qualification kubernetes-check terraform-check restore-drill license-check dependency-audit frontend-install frontend-check frontend-e2e frontend-audit frontend-container-check check compose-config container-check

PYTHON ?= python3
PNPM ?= pnpm

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install the package and development tools
	$(PYTHON) -m pip install --require-hashes -r requirements-dev.lock
	$(PYTHON) -m pip install --no-build-isolation --no-deps -e .

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

protocol-check: ## Validate MCP/A2A versions, boundaries, contracts, and forced RLS
	PYTHONPATH=src $(PYTHON) scripts/check_protocols.py
	PYTHONPATH=src $(PYTHON) -m pytest tests/test_protocols.py tests/test_protocol_adapters.py tests/test_protocol_demo.py

dependency-audit: ## Audit Python vulnerabilities and dependency licenses
	$(PYTHON) -m pip_audit --requirement requirements.lock --progress-spinner off
	$(PYTHON) -m pip_audit --requirement requirements-dev.lock --progress-spinner off
	$(PYTHON) -m piplicenses --format=plain --order=license

license-check: ## Enforce prohibited backend dependency licenses
	$(PYTHON) scripts/check_license_policy.py

production-check: ## Validate Layer 15 deployment, supply-chain, and operations controls
	$(PYTHON) scripts/check_production.py
	$(PYTHON) scripts/check_vulnerability_policy.py

qualification-check: ## Validate Layer 16 readiness, risk, governance, and evidence manifests
	$(PYTHON) scripts/check_qualification.py

qualification-demo: ## Run the canonical no-network checkout qualification
	PYTHONPATH=src $(PYTHON) -m aegis_agent_platform.qualification demo --output .aegis-qualification/demo >/dev/null

qualification-chaos: ## Run bounded deterministic cross-layer recovery scenarios
	PYTHONPATH=src $(PYTHON) -m aegis_agent_platform.qualification chaos-smoke --output .aegis-qualification/chaos.json >/dev/null

qualification-load: ## Run bounded local performance regression profiles
	PYTHONPATH=src $(PYTHON) -m aegis_agent_platform.qualification load-smoke --samples 3 --output .aegis-qualification/load.json >/dev/null

qualification: qualification-check qualification-demo qualification-chaos qualification-load ## Run every Layer 16 local qualification gate

kubernetes-check: production-check ## Render all Kustomize environments
	@for environment in development staging production; do \
		kubectl kustomize "deploy/kubernetes/overlays/$$environment" >/dev/null; \
	done

terraform-check: ## Validate the cost-gated AWS Terraform reference
	terraform -chdir=infra/terraform/aws fmt -check -recursive
	terraform -chdir=infra/terraform/aws init -backend=false -input=false
	terraform -chdir=infra/terraform/aws validate
	terraform -chdir=infra/terraform/aws test
	trivy config --exit-code 1 --severity HIGH,CRITICAL infra/terraform/aws

restore-drill: ## Restore ledger truth in isolation and rebuild derived state
	PYTHON=$(PYTHON) sh scripts/restore_drill.sh

frontend-install: ## Install the exact frontend dependency graph
	$(PNPM) --dir frontend install --frozen-lockfile

frontend-check: ## Run frontend lint, types, unit, accessibility, contract, and build gates
	$(PNPM) --dir frontend check

frontend-e2e: ## Run deterministic Chromium operator journeys
	$(PNPM) --dir frontend e2e

frontend-audit: ## Audit production frontend dependencies
	$(PNPM) --dir frontend audit

frontend-container-check: ## Build the non-root static operator image
	docker build --check frontend
	docker build --tag aegis-operator-ui:local frontend

check: format-check lint type test evals docs-check manifest-check migration-check observability-check protocol-check production-check qualification-check license-check ## Run all fast local checks

compose-config: ## Render and validate the local Compose configuration
	docker compose --env-file .env.example config --quiet

container-check: frontend-container-check ## Build the non-root application images
	docker build --check .
	docker build --tag aegis-agent-platform:local .
