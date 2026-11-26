# ADR 0004: Hiccup is entirely controllable from the CLI

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Hiccup must be fully controllable from the command line. That serves scripting, CI and remote shells, and users who prefer the terminal. The CLI must also be able to drive a Hiccup instance that is **already running**, whether that is a headless daemon or a GUI. For example, `hiccup intercept forward 42` can act on the request currently shown in the GUI.

## Decision

- **Control API.** The core exposes one versioned control API: **JSON-RPC 2.0** with server-push notifications for events, in the `hiccup-control` crate. Every user-visible feature is an operation on this API. Nothing is GUI-only.
- **Transport:** local IPC only. On Linux/macOS this is a Unix domain socket in the per-user runtime directory (`$XDG_RUNTIME_DIR`, or the platform equivalent) with `0600` permissions. On Windows it is a named pipe whose DACL is restricted to the current user. There is no TCP listener by default.
- **Instances.** Each running Hiccup (the daemon `hiccup serve`, or any GUI) hosts a control server and registers itself in a per-user instance registry. The CLI auto-discovers a single instance, and `--instance <name>` selects one when several are running.
- **CLI** (`hiccup`): a client of the control API.
  - Long-running commands either attach to an instance or start an embedded one (`hiccup proxy start --foreground`).
  - Output is human-readable by default, with `--json` for machine-readable output that is stable across minor versions.
  - Commands are non-interactive, with meaningful exit codes, and `hiccup events` streams events.
- **Frontends.** GUIs link the core in-process, and they also host the control server. A CLI user and a GUI user then see and change the same state live.
- **Parity rule.** A feature is "done" only when it is reachable from the CLI. Every milestone's parity checklist includes the CLI.

## Consequences

- One API serves every frontend, so the control API is also a natural testing seam and is reusable by the FFI layer.
- Because the control API is a security boundary, it is local-only, scoped to the user and versioned. Any future remote access needs its own ADR, with authentication and TLS.
- The JSON-RPC schema must be versioned and documented. Breaking changes follow SemVer.
