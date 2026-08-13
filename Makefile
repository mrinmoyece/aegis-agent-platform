.DEFAULT_GOAL := help
.PHONY: help install format format-check lint type test docs-check manifest-check check compose-config container-check

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

docs-check: ## Validate documentation links and required content
	$(PYTHON) scripts/check_docs.py

manifest-check: ## Validate repository configuration manifests
	$(PYTHON) scripts/check_manifests.py

check: format-check lint type test docs-check manifest-check ## Run all fast local checks

compose-config: ## Render and validate the local Compose configuration
	docker compose --env-file .env.example config --quiet

container-check: ## Build the non-root application image
	docker build --check .
	docker build --tag aegis-agent-platform:local .
