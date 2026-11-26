# Define MSRV and toolchain policy

labels: type:chore, area:build

## Goal

Make the supported Rust version explicit and reproducible.

## Tasks

- [ ] Add `rust-toolchain.toml` (stable, with rustfmt and clippy components)
- [ ] Set `rust-version` in the workspace and document the MSRV bump policy (bumps are minor-version changes)
- [ ] CI job that builds on the MSRV

## Acceptance criteria

- [ ] The MSRV job passes
- [ ] Policy documented in CONTRIBUTING.md
