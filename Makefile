# SPDX-License-Identifier: Apache-2.0
# Make targets for the pqc-readiness repo.  Keep this stupid simple —
# the project's only runtime dep is the Python stdlib (numpy is optional).

PY ?= python3
RUFF ?= ruff
MYPY ?= mypy
PODMAN ?= podman
IMAGE ?= pqc-readiness:dev

.PHONY: help test lint typecheck check container-build clean

help:
	@grep -E '^[a-zA-Z_-]+:.*##' Makefile | awk -F':.*##' '{printf "  %-20s %s\n", $$1, $$2}'

test: ## Run the pytest suite
	$(PY) -m pytest tests/ -q

lint: ## ruff lint
	$(RUFF) check pqc_readiness.py tests/

typecheck: ## mypy strict
	$(MYPY) --strict pqc_readiness.py

check: lint typecheck test ## All of the above

container-build: ## Build the UBI 10 minimal container with podman
	$(PODMAN) build --format=docker -t $(IMAGE) -f Containerfile .

clean: ## Remove pytest / mypy / ruff caches
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__ tests/__pycache__
