# Proxy integration and end-to-end test suite

labels: type:test, area:proxy

## Goal

Prove the proxy works the same everywhere.

## Tasks

- [ ] In-process test HTTP and HTTPS servers
- [ ] Scenarios: keep-alive, chunked, large bodies, CONNECT pass-through, MITM, intercept edit, upstream errors
- [ ] Runs in the CI matrix

## Acceptance criteria

- [ ] The suite passes on Linux, macOS and Windows
