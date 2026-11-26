# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, minor versions may contain breaking changes, including in the CLI's `--json` output and the control API. See [docs/releasing.md](docs/releasing.md).

## [Unreleased]

### Added

- Cargo workspace with the `hiccup` CLI binary and crates for the core, the HTTP codec, the proxy, storage and the control API.
- Cross-platform CI (Linux, macOS, Windows): formatting, clippy, tests, MSRV, docs, dependency policy (cargo-deny) and coverage.
- Release workflow that builds CLI binaries for 6 targets and drafts a GitHub Release.
- Community health files: contributing guide, Code of Conduct, security policy, issue and PR templates.
- Roadmap, milestones and architecture decision records.

[Unreleased]: https://github.com/dehy/hiccup/commits/main
