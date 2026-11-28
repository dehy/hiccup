# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, minor versions may contain breaking changes, including in the CLI's `--json` output and the control API. See [docs/releasing.md](docs/releasing.md).

## [Unreleased]

### Added

- Repeater helpers (`hiccup_proxy::Helpers`), all off by default: update `Content-Length` to the body, follow redirects (never, always or in scope only, up to a limit; 303, and 301/302 after a `POST`, become a `GET`; a redirect to another origin drops `Authorization`, `Cookie` and `Proxy-Authorization`), and reuse the connection between sends (retried once on a new one if it was closed while idle). Each send says which helpers changed it (`Sent::applied`) and keeps the bytes it really sent. With the helpers off, the bytes sent are the bytes given.
- Raw request sender (`hiccup_proxy::Sender`), the base of the repeater: it sends exactly the bytes given, malformed or not, to a target (host, port, TLS) set apart from the `Host` header, with the proxy's upstream options (TLS versions, verification, SNI, `--resolve`, client certificates). It reads the response with the codec, interim responses included, and keeps every byte received, the timings (DNS, connect, TLS, time to first byte, total) and why it failed. A send can be cancelled, and each step has a timeout.
- CLI: `hiccup config get|set|unset` saves defaults for `--project`, `proxy start --listen` and `--no-verify-upstream` (flags win); `-q` logs errors only; `hiccup completions <shell>` (bash, zsh, fish, PowerShell) and `hiccup man --output DIR` generate completions and man pages. Exit codes are documented in `docs/cli.md`: 0 success, 1 failure, 2 usage error.
- History recording. `--project FILE` makes an instance started by `hiccup serve` or `hiccup proxy start --foreground` record every exchange in that project file, which survives restarts. Exchanges are queued, so the proxy never waits on the disk; a queue that falls behind drops (with a warning) rather than slows the proxy.
  - Control API: `history.list` (filters, newest first, paginated) and `history.show` (the exact bytes, base64-encoded). `instance.info` gives the open project.
  - CLI: `hiccup history list|show|export`. `show --request` / `--response` write the exact bytes when redirected; `export` writes every matching exchange as one JSON object per line.
- A project file another user created is refused, untouched (on Windows, by checking the file's owner before opening it). On Unix, a project is also refused if another user could swap it before it is opened: when it is a symbolic link, or in a directory others can write to (sticky directories like `/tmp` are fine).
- Event stream. After `events.subscribe`, a control connection receives `exchange.request`, `exchange.response` (with the error, if any), `intercept.pending`, `intercept.resolved` and `proxy.state` events. Buffers are bounded: a subscriber that falls behind gets `events.lagged`, then is dropped. `hiccup events [--json] [--filter PREFIX]` streams them, escaping text from traffic on a terminal, and subscribes again after a lag.
  - `Exchange::id` ties a request to its completion; `Proxy::with_request_observer` is told of each request before it is held or forwarded. `InterceptQueue::with_listener` is told of every change to the queue.
- Target scope: include and exclude rules on protocol, host pattern, port and a path regex. In scope is what matches an include rule and no exclude rule; with no include rule, everything not excluded is. The scope belongs to the instance.
  - Control API: `scope.list`, `scope.add`, `scope.remove` and `scope.test`. CLI: `hiccup scope add|remove|list|test <url>`.
  - Intercept rules can be limited to the scope (`in_scope`, `hiccup intercept on --in-scope`), and history queries filter by it (`Filter::scope`).
- Response bodies are relayed as they arrive (server-sent events, downloads, video), instead of being read in full first. An exchange keeps up to `ProxyConfig::max_kept_body` (8 MiB) of the body and records `response_truncated` beyond that, which the store saves too. A response held in the intercept queue is still read in full.
- Request bodies are relayed as they arrive too (uploads, `curl -T -`), on a new upstream connection, since a streamed body cannot be resent if a reused one turns out to be closed. An exchange keeps up to `max_kept_body` of the request and records `request_truncated` beyond that (in the store and in `history.list`). A request that matches the intercept rules, or that was already received whole, is still read in full.
- `hiccup proxy start` warns when the proxy listens beyond loopback: anyone who can reach it can use it without authentication.
- `hiccup-store`: proxy history in a SQLite project file (`.hiccup`). Every exchange keeps its exact bytes (received, forwarded, interim, response, delivered), timings, TLS flag and edited flags. Raw messages live in a separate blob table, and schema migrations are tracked with `user_version`.
  - Newest-first pages filtered by host, method, status, media type prefix and byte search.
  - 10k exchanges: p95 under 50 ms to insert and to query (`cargo test --release -p hiccup-store -- --ignored`).
- `Exchange::started` and `Exchange::duration`.
- Intercept queue. Matching requests and responses are held until they are forwarded, forwarded edited (the bytes are sent exactly as edited), or dropped. After an edited request, the upstream connection is not reused.
  - Rules per direction match the request's host patterns, methods and a path regex.
  - An optional timeout forwards or drops whatever nobody acts on.
  - Exchanges record `RequestEdited` and `ResponseEdited`, and an edited response's bytes are kept in `Exchange::delivered`.
  - Control API: `intercept.status`, `intercept.set`, `intercept.list`, `intercept.show`, `intercept.forward`, `intercept.drop` and `intercept.forward_all`.
  - CLI: `hiccup intercept on|off|status|list|show|forward|drop|edit`. `edit` takes `--file`, standard input, or `$VISUAL`/`$EDITOR`.
  - On a terminal, `show` and `list` escape control characters; redirected, `show` writes the exact bytes.
- Control plane (ADR 0004): every running Hiccup is an instance that other `hiccup` commands control.
  - `hiccup-control`: JSON-RPC 2.0 over a Unix socket (`0600`, in a `0700` directory) or a Windows named pipe restricted to its owner, with server-push notifications and a per-user instance registry. The API reference (`docs/control-api.md`) is generated from the code.
  - `hiccup serve` runs a headless instance. `hiccup proxy start|stop|status` and `hiccup instance list|stop` control it. `proxy start --foreground` is an instance too.
  - Global options: `--instance NAME` (`HICCUP_INSTANCE`), `--json`, and `--runtime-dir` (`HICCUP_RUNTIME_DIR`).
  - `hiccup ca info --json`.
- Upstream connection options for `hiccup proxy start`:
  - Upstream server certificates are verified against the OS trust store by default (`UpstreamConfig::default()`, `proxy.start`). `--no-verify-upstream` turns verification off, to test targets with self-signed or invalid certificates, and startup warns about it.
  - `--upstream-tls-min` and `--upstream-tls-max` take 1.2 or 1.3; rustls cannot reach TLS 1.0/1.1-only servers.
  - Per-host rules, `HOST=VALUE`, with the same patterns as `--tls-passthrough`; the first match applies:
    - `--upstream-sni` overrides the server name;
    - `--resolve` connects to a fixed IP instead of resolving the host;
    - `--client-cert HOST=CERT[,KEY]` presents a client certificate.
  - `--connect-timeout` and `--read-timeout`, in seconds.
- HTTPS interception in `CONNECT` tunnels.
  - The client gets a certificate for the host (from SNI, else the `CONNECT` target; DNS name or IP), signed by the local CA and cached per host. ALPN is limited to `http/1.1`.
  - Requests inside the tunnel are forwarded as received, over TLS, and recorded like plain ones (`Exchange::tls`).
  - `hiccup proxy start --tls-passthrough PATTERN` (`host`, `*.example.com` or `*`) relays matching hosts untouched, as are tunnels that do not carry TLS.
- Local certificate authority for HTTPS interception: an ECDSA P-256 root CA, generated per installation on first use and stored in the per-user data directory with an owner-only private key.
  - `hiccup ca info` shows its location, validity and SHA-256 fingerprint.
  - `hiccup ca export [--format pem|der] [-o FILE]` exports the certificate.
  - `hiccup ca regenerate --yes` replaces it.
  - The global `--data-dir` option (or `HICCUP_DATA_DIR`) overrides the data directory.
  - [Install guide](docs/ca.md) for Firefox, Linux, macOS and Windows.
- `hiccup-proxy`: explicit HTTP/1.1 proxy.
  - Absolute-form requests are forwarded in origin-form, and the rewrite is recorded. Every other byte, including hop-by-hop headers, is forwarded as received.
  - Keep-alive on both sides with upstream reuse, a retry for idempotent requests on stale connections, and pipelining.
  - Interim 1xx responses are relayed, and `101` upgrades are tunnelled.
  - `CONNECT` tunnels (pass-through).
  - Hiccup answers with its own 4xx/5xx error responses when it can't proceed.
  - Graceful shutdown, and an observer for completed exchanges.
- `hiccup proxy start --foreground [--listen ADDR]...` runs the proxy in the terminal until Ctrl+C.
- `hiccup-http`: raw-preserving HTTP/1.1 codec. It has a lenient head tokenizer with anomaly reporting, RFC 9112 framing with smuggling-relevant ambiguities flagged, a streaming chunked/length/until-close body decoder, and byte-identical round trips. It is fuzzed in CI (ADR 0006).
- Cargo workspace with the `hiccup` CLI binary and crates for the core, the HTTP codec, the proxy, storage and the control API.
- Cross-platform CI (Linux, macOS, Windows): formatting, clippy, tests, MSRV, docs, dependency policy (cargo-deny) and coverage.
- Release workflow that builds CLI binaries for 6 targets and drafts a GitHub Release.
- Community health files: contributing guide, Code of Conduct, security policy, issue and PR templates.
- Roadmap, milestones and architecture decision records.

[Unreleased]: https://github.com/dehy/hiccup/commits/main
