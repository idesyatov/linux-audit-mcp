# Makefile — wrappers around docker compose.
# Rust is not required on the host: build/test/lint run inside the container.
# Requires: docker, docker compose, git, make.

.DEFAULT_GOAL := help

# Crate version from Cargo.toml.
CARGO_VERSION := $(shell grep -m1 '^version' Cargo.toml | sed -E 's/.*"(.*)".*/\1/')

.PHONY: help build dev test lint build-release check version clean

help: ## Show the list of targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the dev image
	docker compose build dev

dev: ## Interactive development (cargo watch)
	docker compose up dev

test: ## Run tests
	docker compose run --rm test

lint: ## fmt --check + clippy (-D warnings)
	docker compose run --rm lint

build-release: ## Release build of the binary in the container
	docker compose run --rm build-release

check: lint test ## Full pre-release check (same as CI)

version: ## Print the crate version from Cargo.toml
	@echo $(CARGO_VERSION)

clean: ## Remove containers and volumes (cargo/target caches)
	docker compose down -v
