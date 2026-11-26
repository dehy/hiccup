# Architecture

Hiccup is a Rust core with thin frontends. Read the [ADRs](adr/) for the reasoning behind each decision.

```
            ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐
frontends   │ hiccup CLI  │  │ GTK4 (Linux)│  │SwiftUI (mac)│  │WinUI 3 (Win) │
            └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘
                   │ control API    │ in-process     │ FFI (UniFFI)    │ FFI
                   ▼                ▼                ▼                 ▼
            ┌──────────────────────────────────────────────────────────────────┐
core        │ hiccup-control ── hiccup-core ── hiccup-proxy ── hiccup-http     │
            │                        └──────── hiccup-store                    │
            └──────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate            | Responsibility |
|------------------|----------------|
| `hiccup-core`    | Domain model, services, view-models shared by all frontends. Composes the other crates. |
| `hiccup-http`    | Raw-preserving HTTP/1.1 codec: exact bytes plus a derived parsed view ([ADR 0003](adr/0003-raw-http-fidelity.md)). |
| `hiccup-proxy`   | Intercepting proxy: listeners, CONNECT, TLS MITM, CA and leaf certificates, intercept queue. |
| `hiccup-store`   | Project files and traffic history in SQLite. |
| `hiccup-control` | Local control API: JSON-RPC 2.0 over Unix socket / named pipe, instance discovery ([ADR 0004](adr/0004-cli-control-plane.md)). |
| `hiccup-cli`     | The `hiccup` binary: a client of the control API, and the headless daemon (`hiccup serve`). |

Planned for later milestones: `hiccup-ffi` (M3, UniFFI bindings for Swift/C#) and `hiccup-gtk` (M4). They are not in the workspace yet, so that we don't carry empty crates or unused dependencies.

## Rules

- **Thin frontends:** no protocol logic outside the core ([ADR 0001](adr/0001-architecture-native-frontends.md)).
- **CLI parity:** every feature is reachable through the control API and the CLI ([ADR 0004](adr/0004-cli-control-plane.md)).
- **No `unsafe`** by default (`unsafe_code = "deny"` workspace lint). Exceptions, such as FFI, must be justified and scoped to one crate.
