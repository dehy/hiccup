# ADR 0003: Raw HTTP wire fidelity

- **Status:** Accepted, amended by [ADR 0006](0006-own-http-tokenizer.md) (no httparse)
- **Date:** 2026-11-26

## Context

Security testers need to see and send exactly the bytes on the wire: duplicate headers, odd casing, unusual header order, bare `\n` line endings, conflicting `Content-Length`/`Transfer-Encoding`, and malformed request lines. General-purpose HTTP stacks such as `hyper` parse messages into normalized structures and refuse or rewrite malformed input, which hides exactly the behaviour we want to test.

## Decision

- Hiccup has its own HTTP/1.1 codec (`hiccup-http`). It is built on `httparse` for tokenizing, but always **keeps the original bytes** next to the parsed view.
- The canonical stored form of every message is its **raw bytes**. Parsed fields are a derived, read-only view.
- The proxy forwards the raw bytes unchanged, unless the user edited the message or a configured rule rewrites it. Any rewrite is explicit and recorded.
- The Repeater sends exactly the bytes in the editor. Helpers such as Content-Length auto-update are opt-in and visible.
- TLS uses `rustls`, and certificates are generated with `rcgen`.

## Consequences

- We own a security-sensitive parser. It needs fuzzing (`cargo-fuzz`) and a large corpus of edge-case tests.
- HTTP/2 needs a separate design later. Frame-level fidelity is a different problem.
- Lenient parsing must never panic or allocate without limits on hostile input. Limits are configurable.
