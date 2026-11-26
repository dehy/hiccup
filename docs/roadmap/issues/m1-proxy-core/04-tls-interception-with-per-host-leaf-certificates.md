# TLS interception with per-host leaf certificates

labels: type:feature, area:tls

## Goal

Man-in-the-middle HTTPS traffic for inspection.

## Tasks

- [ ] After CONNECT, terminate TLS with `rustls` using a leaf cert generated for the SNI or CONNECT host (SAN DNS or IP)
- [ ] LRU cache of leaf certs
- [ ] ALPN restricted to `http/1.1` (HTTP/2 is a later milestone)
- [ ] Per-host interception exclusions (pass-through)

## Acceptance criteria

- [ ] A browser with the CA installed loads HTTPS sites through the proxy without warnings
- [ ] Integration test against a local TLS test server
