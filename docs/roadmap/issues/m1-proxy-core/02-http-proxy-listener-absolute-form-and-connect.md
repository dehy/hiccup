# HTTP proxy listener (absolute-form and CONNECT)

labels: type:feature, area:proxy

## Goal

Accept browser and tool traffic as an explicit HTTP proxy.

## Tasks

- [ ] Async listener (tokio) on a configurable address:port, defaulting to `127.0.0.1:8080`
- [ ] Absolute-form requests forwarded upstream; keep-alive both ways
- [ ] `CONNECT` tunnelling (pass-through when TLS interception is off for a host)
- [ ] Graceful shutdown; per-connection tracing spans
- [ ] Multiple listeners

## Acceptance criteria

- [ ] curl `-x` works for plain HTTP and for CONNECT pass-through on all 3 OSes
