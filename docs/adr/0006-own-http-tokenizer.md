# ADR 0006: Own lenient HTTP/1.1 tokenizer instead of httparse

- **Status:** Accepted
- **Date:** 2026-11-26
- **Amends:** [ADR 0003](0003-raw-http-fidelity.md). It replaces 0003's "built on `httparse` for tokenizing"; the rest of 0003 stands.

## Context

ADR 0003 planned to tokenize heads with `httparse` and keep the raw bytes next to its output. Before implementing, we ran `httparse` 1.x over 24 edge cases that a security proxy must handle, with its leniency options on (`allow_multiple_spaces_in_request_line_delimiters`, `ignore_invalid_headers_in_requests`).

`httparse` **rejects**:

- control characters or NUL in a header value;
- a tab or several spaces in the request line;
- `HTTP/1.2`, or a request line with no version (HTTP/0.9);
- a space inside the request target.

In lenient mode, it **silently drops**:

- headers with whitespace before the colon (`Transfer-Encoding : chunked`, a classic request-smuggling vector);
- headers with invalid name characters;
- the continuation lines of obsolete line folding;
- lines without a colon.

A proxy built on it would either fail on these messages or forward bytes that its own parsed view hides from the user. That contradicts the principle of ADR 0003.

## Decision

`hiccup-http` uses its own small tokenizer:

- It splits the head into lines at LF (CR optional), and interprets the start line and header fields as byte spans into the raw bytes.
- It **never rejects** malformed syntax. Each deviation from RFC 9112 is recorded as an `Anomaly` (kind plus span), for example `WhitespaceBeforeColon`, `ObsFold`, `BareLf` or `InvalidHeaderValue`.
- Hard errors are only resource-limit violations (head size, field count, chunk line and trailer size) and chunked framing that cannot be followed.
- Framing follows RFC 9112 §6.3. Ambiguities (CL+TE, duplicate or conflicting Content-Length, non-final `chunked`) are resolved the way the RFC says a recipient should, and are flagged.
- Header names are matched **verbatim**, case-insensitively, so `Transfer-Encoding ` (with a trailing space) does not count as `Transfer-Encoding` for framing. Like a strict server, the proxy then ignores it for framing, while the anomaly shows the user that it is there.

## Consequences

- There is no parsing dependency, and the code is small enough to audit: about 1,700 lines without tests (much of it doc comments).
- We own a security-sensitive parser. It is covered by unit tests, a round-trip corpus, property tests (`proptest`) and `cargo-fuzz` targets that run in CI.
- Head parsing rescans the buffer on each attempt until the head is complete. This is fine for the 64 KiB head limit; optimise it if profiling shows a need.
