# Hiccup Roadmap

This document describes where Hiccup is going and in which order. Each milestone maps 1:1 to a GitHub Milestone. Its issues are drafted in [`docs/roadmap/issues/`](docs/roadmap/issues/), and [`scripts/github-bootstrap.sh`](scripts/github-bootstrap.sh) pushes them to GitHub.

## Vision

Hiccup is a free, open source, cross-platform toolkit for web application security testing. It starts with the two tools pentesters use most: an **intercepting proxy** and a **Repeater**.

## Principles

1. **Wire fidelity.** What you see is what was sent. Hiccup never silently normalizes requests or responses: it keeps header order, header case and malformed messages as they were (see [ADR 0003](docs/adr/0003-raw-http-fidelity.md)).
2. **Thin native frontends, fat core.** All logic lives in the Rust core. Each OS gets a truly native UI that only renders view-models (see [ADR 0001](docs/adr/0001-architecture-native-frontends.md)).
3. **Entirely controllable from the CLI.** Every feature is reachable from the `hiccup` CLI, and the CLI can drive a running instance (headless daemon or GUI) over a local control API. A feature is not done until it works from the CLI (see [ADR 0004](docs/adr/0004-cli-control-plane.md)).
4. **Cross-platform from day one.** CI runs on Linux, macOS and Windows for every change.
5. **Local and private.** No telemetry and no cloud dependency. Your traffic stays on your machine.

## Milestones

| #  | Milestone | Goal | Exit criteria | Release | Status |
|----|-----------|------|---------------|---------|--------|
| M0 | [Foundations](docs/roadmap/issues/m0-foundations/) | Workspace, CI, community health files | CI green on Linux, macOS, Windows | — | ✅ Done |
| M1 | [Proxy core](docs/roadmap/issues/m1-proxy-core/) | Headless HTTP/1.1 + HTTPS MITM proxy with history, intercept and CLI control API | curl and a browser work through the proxy, driven entirely by the CLI, on all 3 OSes | — | In progress |
| M2 | [Repeater core](docs/roadmap/issues/m2-repeater-core/) | Headless raw request sender with persisted tabs | Replaying a captured request is byte-identical, which tests verify | — | Planned |
| M3 | [FFI layer](docs/roadmap/issues/m3-ffi/) | Core API exposed to Swift and C# | Swift and C# smoke tests pass in CI on macOS and Windows | — | Planned |
| M4 | [Linux frontend](docs/roadmap/issues/m4-linux-frontend/) | GTK4 + libadwaita UI for proxy and repeater | Full proxy + repeater workflow usable; packages built | **v0.1.0** | Planned |
| M5 | [macOS frontend](docs/roadmap/issues/m5-macos-frontend/) | SwiftUI UI at parity with M4 | Parity checklist passes; notarized .dmg | v0.2.0 | Planned |
| M6 | [Windows frontend](docs/roadmap/issues/m6-windows-frontend/) | WinUI 3 UI at parity with M4 | Parity checklist passes; signed MSIX/MSI | v0.3.0 | Planned |

The Linux frontend comes first because it is the primary development platform. macOS and Windows follow. The core is cross-platform from M0, so the headless CLI works on all three OSes well before their GUIs exist.

### M0: Foundations
Cargo workspace (`hiccup-core`, `hiccup-http`, `hiccup-proxy`, `hiccup-store`, `hiccup-control`, `hiccup-cli`; `hiccup-ffi` arrives with M3), MSRV policy, rustfmt/clippy/cargo-deny, a GitHub Actions matrix (ubuntu/macos/windows), CONTRIBUTING, Code of Conduct, SECURITY policy, issue/PR templates, Conventional Commits + DCO, CHANGELOG, and the release process.

### M1: Proxy core (headless)
HTTP/1.1 listener (absolute-form + `CONNECT`), raw-preserving HTTP/1.1 codec, CA generation/persistence/export, per-host leaf certificates with an LRU cache, upstream TLS options (skip verification, SNI override), an intercept queue (forward/drop/edit, per direction), history in SQLite, scope rules, an event stream API, the **local control API** (JSON-RPC over Unix socket / named pipe) with the `hiccup serve` daemon and instance discovery, `hiccup proxy …`, `hiccup intercept …` and `hiccup history …` commands with `--json`, and integration tests.

### M2: Repeater core (headless)
A raw sender that writes the exact bytes; target separate from the `Host` header; optional Content-Length auto-update; redirect policy; timing and size metrics; persisted tabs with per-tab history; "send to Repeater" from proxy history; `hiccup repeater …` commands over the control API.

### M3: FFI layer
A UniFFI interface for projects, proxy control, intercept, paginated history and repeater; async event callbacks; a Swift package; a spike to choose the C# binding strategy; smoke-test host apps in CI.

### M4: Linux frontend (GTK4 + libadwaita)
Proxy history with filtering, a request/response viewer (raw/headers/hex), the intercept pane, Repeater tabs with an editor, settings (listener, CA export and install guide), an embedded control server so the CLI drives the GUI live, and Flatpak/AppImage/.deb packaging. Ends with **v0.1.0**.

### M5: macOS frontend (SwiftUI)
Parity with M4, a universal binary, a signed and notarized `.dmg`, and a Homebrew cask.

### M6: Windows frontend (WinUI 3)
Parity with M4, MSIX/MSI, a winget manifest, and a CA install helper.

## Backlog (after M6, unordered)

Each item becomes its own milestone when it is scheduled.

- HTTP/2 (proxy + repeater)
- WebSockets interception and history
- Match & replace rules
- Upstream HTTP/SOCKS proxy chaining
- Invisible (transparent) proxy mode
- Decoder (encode/decode/hash)
- Comparer (diff of requests/responses)
- Intruder-style fuzzer
- Sequencer (token randomness analysis)
- Passive scanner
- Extension API (WASM plugins)
- Project import/export (HAR, raw)

## Changing the roadmap

Open an issue labelled `type:roadmap` to propose changes. An architecture-level change also needs a new ADR in [`docs/adr/`](docs/adr/).
