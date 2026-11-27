# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, minor versions may contain breaking changes, including in the CLI's `--json` output and the control API. See [docs/releasing.md](docs/releasing.md).

## [Unreleased]

### Added

- `hiccup-proxy`: explicit HTTP/1.1 proxy.
  - Absolute-form requests are forwarded in origin-form, and the rewrite is recorded. Every other byte, including hop-by-hop headers, is forwarded as received.
  - Keep-alive on both sides with upstream reuse, a retry for idempotent requests on stale connections, and pipelining.
  - Interim 1xx responses are relayed, and `101` upgrades are tunnelled.
  - `CONNECT` tunnels (pass-through).
  - Hiccup answers with its own 4xx/5xx error responses when it can't proceed.
  - Graceful shutdown, and an observer for completed exchanges.
- `hiccup proxy start --foreground [--listen ADDR]...` runs the proxy in the terminal until Ctrl+C.
- `hiccup-http`: raw-preserving HTTP/1.1 codec. It has a lenient head tokenizer with anomaly reporting, RFC 9112 framing with smuggling-relevant ambiguities flagged, a streaming chunked/length/until-close body decoder, and byte-identical round trips. It is fuzzed in CI (ADR 0006).
- Cargo workspace with the `hiccup` CLI binary and crates for the core, the HTTP codec, the proxy, storage and the control API.
- Cross-platform CI (Linux, macOS, Windows): formatting, clippy, tests, MSRV, docs, dependency policy (cargo-deny) and coverage.
- Release workflow that builds CLI binaries for 6 targets and drafts a GitHub Release.
- Community health files: contributing guide, Code of Conduct, security policy, issue and PR templates.
- Roadmap, milestones and architecture decision records.

[Unreleased]: https://github.com/dehy/hiccup/commits/main
