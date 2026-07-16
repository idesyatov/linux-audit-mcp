# Contributing

Thanks for your interest in the project. Below is how to build, verify, and
submit changes. You do not need Rust on the host — everything runs through
Docker Compose.

## Requirements

- `docker` and `docker compose`. Nothing else.

## Workflow

```bash
# Interactive development: cargo watch rebuilds and runs tests
docker compose up dev

# One-off test run
docker compose run --rm test

# Lint: cargo fmt --check + clippy (-D warnings)
docker compose run --rm lint

# Release build
docker compose run --rm build-release
```

The first run builds the dev image and warms the caches (a few minutes). Cargo
caches and `target/` live in named Docker volumes, so repeat runs are fast and
no host `target/` directory is created.

### Updating the image

If `Dockerfile.dev` or dependencies in `Cargo.toml` changed:

```bash
docker compose build dev
```

## Before committing

The same checks that run in CI should pass locally:

```bash
docker compose run --rm lint
docker compose run --rm test
```

CI (`.github/workflows/ci.yml`) runs exactly these services in the same image,
so there should be no divergence between local checks and CI.

## Style

- Formatting — `cargo fmt` (enforced by `lint`).
- Linting — `clippy` with no warnings (`-D warnings`).
- Do not add dependencies to `Cargo.toml` without necessity.
- 🔒 Any command sent to a host must be an exact member of the read-only catalog
  (`src/catalog.rs`). Commands that write or modify state are not added.

## Commits

Format: `type: description` (short and to the point).

Types: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `ci`.

## Pull Requests

- One branch = one logical task.
- In the PR description: what was done and how to verify it.
- Run `lint` and `test` before submitting.
- Do not commit build artifacts (`target/`, `dist/`) or secrets — they are in
  `.gitignore`.
