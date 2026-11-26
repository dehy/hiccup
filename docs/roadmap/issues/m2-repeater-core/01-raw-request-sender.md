# Raw request sender

labels: type:feature, area:repeater

## Goal

Send exactly the bytes the user wrote.

## Tasks

- [ ] Write raw bytes over TCP or TLS (reusing the M1 upstream options)
- [ ] The target (host, port, TLS) is set separately from the `Host` header
- [ ] Read the response with the M1 codec; capture raw bytes, timings (DNS, connect, TLS, TTFB, total) and sizes
- [ ] Cancellation and timeouts

## Acceptance criteria

- [ ] Byte-identical send verified by a capturing test server, including malformed requests
