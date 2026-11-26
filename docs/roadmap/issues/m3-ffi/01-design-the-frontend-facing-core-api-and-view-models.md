# Design the frontend-facing core API and view-models

labels: type:design, area:ffi

## Goal

One API surface, shared by the control API, FFI and GTK, keeps frontends thin.

## Tasks

- [ ] Define view-models (history row, message view with raw/headers/hex, intercept item, repeater tab) in `hiccup-core`
- [ ] Async model and event subscription semantics
- [ ] Write an ADR on API versioning across the control API and FFI

## Acceptance criteria

- [ ] ADR merged; the API is reviewed against the M4 UI wireframes
