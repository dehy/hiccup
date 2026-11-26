# Linting, formatting and dependency policy

labels: type:chore, area:build

## Goal

Enforce code quality and license compatibility automatically.

## Tasks

- [ ] `rustfmt.toml`; `cargo fmt --check` in CI
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` in CI
- [ ] `deny.toml` with an AGPL-compatible license allow-list, an advisories check (RustSec) and banned/duplicate crates
- [ ] `.editorconfig`
- [ ] Dependabot (or Renovate) config for cargo and GitHub Actions

## Acceptance criteria

- [ ] CI fails on formatting, clippy warnings, a disallowed license or a known advisory
