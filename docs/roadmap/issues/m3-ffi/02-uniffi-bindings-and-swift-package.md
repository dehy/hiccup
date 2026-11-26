# UniFFI bindings and Swift package

labels: type:feature, area:ffi, platform:macos

## Goal

Generate Swift bindings for the core.

## Tasks

- [ ] `hiccup-ffi` with UniFFI (proc-macro interface)
- [ ] Async functions and callback interfaces for events
- [ ] Build an XCFramework (arm64 + x86_64) and a Swift Package

## Acceptance criteria

- [ ] A Swift smoke test starts a proxy, receives an event and sends a repeater request in CI on macOS
