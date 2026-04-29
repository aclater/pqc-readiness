# SPDX-License-Identifier: Apache-2.0
# Make targets for the pqc-readiness repo.  Keep this stupid simple —
# the project's only runtime dep is the Python stdlib (numpy is optional).

PY ?= python3
RUFF ?= ruff
MYPY ?= mypy
PODMAN ?= podman
IMAGE ?= pqc-readiness:dev
IMAGE_UBI8 ?= pqc-readiness:ubi8
IMAGE_UBI10 ?= pqc-readiness:ubi10
IMAGE_DEBIAN ?= pqc-readiness:debian

.PHONY: help test lint typecheck check check-readme container container-build container-ubi8 container-ubi10 container-debian clean

help:
	@grep -E '^[a-zA-Z_-]+:.*##' Makefile | awk -F':.*##' '{printf "  %-20s %s\n", $$1, $$2}'

test: ## Run the pytest suite
	$(PY) -m pytest tests/ -q

lint: ## ruff lint
	$(RUFF) check pqc_readiness.py tests/

typecheck: ## mypy strict
	$(MYPY) --strict pqc_readiness.py

check: lint typecheck test ## All of the above

check-readme: ## Verify README.md documents every --help flag
	@bash scripts/check-readme-flags.sh

container-build: container-ubi10 ## Alias for container-ubi10 (back-compat)

container: container-ubi8 container-ubi10 container-debian ## Build all three container images

container-ubi8: ## Build the UBI 8 minimal container (RHEL 8 / Rocky 8 / AlmaLinux 8) with podman
	$(PODMAN) build --format=docker -t $(IMAGE_UBI8) -f Containerfile.ubi8 .

container-ubi10: ## Build the UBI 10 minimal container with podman
	$(PODMAN) build --format=docker -t $(IMAGE_UBI10) -f Containerfile.ubi10 .

container-debian: ## Build the Debian 12-slim container with podman
	$(PODMAN) build --format=docker -t $(IMAGE_DEBIAN) -f Containerfile.debian .

clean: ## Remove pytest / mypy / ruff caches
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__ tests/__pycache__
