# ADR 0005: Hand-written release workflow (for now)

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

We need reproducible release artifacts for Linux, macOS and Windows. The two popular Rust options were evaluated:

- **cargo-dist** generates the CI workflow, archives, checksums, and shell/PowerShell installers. It focuses on CLI binaries, and the workflow it generates is regenerated rather than hand-edited.
- **release-plz** automates version bumps, changelogs and crates.io publishing from Conventional Commits, via release PRs.

Hiccup's needs:

- Today it ships one CLI binary, and its crates are not published (`publish = false`).
- From M4 on it ships native GUI packages that neither tool builds: Flatpak, AppImage, .deb/.rpm, a notarized .dmg, MSIX/MSI.

## Decision

- Use a **small hand-written GitHub Actions workflow** (`.github/workflows/release.yml`). It builds the CLI for 6 targets, packages archives with `SHA256SUMS`, and creates a **draft** release on version tags. A manual run is a dry run.
- Maintain the version and changelog **manually**, following Keep a Changelog ([docs/releasing.md](../releasing.md)).
- Revisit this decision at M4, when GUI packaging is added. Two triggers:
  - Adopt **cargo-dist** if CLI installers (curl | sh, Homebrew, winget for the CLI) become a priority.
  - Adopt **release-plz** if we start publishing crates or the manual changelog becomes a burden.

## Consequences

- There is no extra tool to learn, and the workflow is short and easy to audit (actions are pinned by SHA).
- Version bumps and changelog editing are manual steps in the checklist.
- Artifact signing (Sigstore/cosign or GitHub artifact attestations) is not done yet. It is tracked for the first public release.
