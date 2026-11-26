# Raw-preserving HTTP/1.1 codec

labels: type:feature, area:http

## Goal

Parse HTTP/1.1 messages while keeping the exact original bytes (ADR 0003).

## Tasks

- [ ] A message model that stores raw bytes plus a derived parsed view (request line / status line, ordered headers keeping their case, body)
- [ ] Framing: Content-Length, chunked (including trailers), read-until-close, `Expect: 100-continue`, HEAD/204/304 bodies
- [ ] Lenient mode for malformed input; configurable size limits (header bytes, header count, body)
- [ ] Never panic on hostile input

## Acceptance criteria

- [ ] A round trip of parse → serialize is byte-identical over a corpus of edge cases (duplicate headers, odd casing, bare LF, obs-fold, CL+TE)
- [ ] A `cargo-fuzz` target exists and runs in CI for a short time
