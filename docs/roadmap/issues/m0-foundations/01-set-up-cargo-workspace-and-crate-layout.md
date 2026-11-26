# Set up Cargo workspace and crate layout

labels: type:chore, area:build

## Goal

Create the workspace skeleton that all later milestones build on.

## Tasks

- [ ] Root `Cargo.toml` with `[workspace]`, shared `[workspace.package]` (edition 2021, `license = "AGPL-3.0-or-later"`, repository, rust-version)
- [ ] Crates: `hiccup-core`, `hiccup-http`, `hiccup-proxy`, `hiccup-store`, `hiccup-control`, `hiccup-cli` (binary `hiccup`). `hiccup-ffi` is added in M3, so that we don't carry an empty crate
- [ ] Shared `[workspace.dependencies]` and `[workspace.lints]`
- [ ] SPDX header on every source file
- [ ] Document crate responsibilities in `docs/architecture.md`

## Acceptance criteria

- [ ] `cargo build --workspace` and `cargo test --workspace` succeed on Linux, macOS and Windows
- [ ] `hiccup --version` prints the version
