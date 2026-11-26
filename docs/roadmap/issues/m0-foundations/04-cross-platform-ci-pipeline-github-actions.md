# Cross-platform CI pipeline (GitHub Actions)

labels: type:chore, area:ci, platform:linux, platform:macos, platform:windows

## Goal

Every PR is built and tested on all three supported OSes.

## Tasks

- [ ] Workflow matrix: `ubuntu-latest`, `macos-latest`, `windows-latest`
- [ ] Jobs: fmt, clippy, test, deny, MSRV, docs (`cargo doc -D warnings`)
- [ ] Cache with `Swatinem/rust-cache`
- [ ] Pin actions by commit SHA and use minimal `permissions:`
- [ ] Code coverage (cargo-llvm-cov) reported, not gating

## Acceptance criteria

- [ ] A green run on all three OSes is required for merge (branch protection documented)
