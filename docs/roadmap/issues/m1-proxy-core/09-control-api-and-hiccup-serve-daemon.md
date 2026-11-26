# Control API and `hiccup serve` daemon

labels: type:feature, area:control

## Goal

Implement the local control plane that makes Hiccup entirely controllable from the CLI (ADR 0004).

## Tasks

- [ ] `hiccup-control`: a JSON-RPC 2.0 schema (versioned) with server-push notifications
- [ ] Transport: Unix socket (0600) on Linux/macOS, a named pipe restricted to the current user on Windows
- [ ] A per-user instance registry; discovery and `--instance` selection
- [ ] `hiccup serve [--project FILE]` runs a headless instance
- [ ] Generated API reference docs

## Acceptance criteria

- [ ] The CLI attaches to a running daemon on all 3 OSes
- [ ] Another local user cannot connect (tested on Linux/macOS)
