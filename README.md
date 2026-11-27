# Hiccup

[![CI](https://github.com/dehy/hiccup/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dehy/hiccup/actions/workflows/ci.yml?query=branch%3Amain)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=dehy_hiccup&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dehy_hiccup)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=dehy_hiccup&metric=coverage)](https://sonarcloud.io/component_measures?id=dehy_hiccup&metric=coverage)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](LICENSE)

An open source, cross-platform web security testing toolkit written in Rust. Hiccup is an intercepting HTTP(S) proxy with a Repeater and native desktop interfaces for Linux, macOS and Windows.

> **Status:** pre-alpha. The headless proxy works from the CLI, with HTTPS interception, an intercept queue and history, but there is no Repeater or GUI yet. Expect breaking changes. See the [roadmap](ROADMAP.md).

Hiccup is an independent project. It is not affiliated with or endorsed by PortSwigger Ltd. "Burp Suite" is a trademark of PortSwigger Ltd.

## Goals

- **Intercepting proxy:** HTTP/1.1 and HTTPS (TLS MITM with a locally generated CA).
- **Repeater:** edit and resend requests while keeping the exact bytes.
- **Native UIs:** GTK4 on Linux, SwiftUI on macOS and WinUI 3 on Windows, all on a shared Rust core.
- **Entirely controllable from the CLI:** every feature is available from `hiccup`, which can also drive a running instance, including the GUI.

## Building from source

```sh
cargo build --release
./target/release/hiccup --help
```

## Quick start

```sh
hiccup proxy start --foreground            # listens on 127.0.0.1:8080, until Ctrl+C
curl -x http://127.0.0.1:8080 http://example.com/

# HTTPS is decrypted with a CA generated for your installation:
hiccup ca export -o hiccup.pem
curl -x http://127.0.0.1:8080 --cacert hiccup.pem https://example.com/
```

Or run Hiccup in the background and control it from any terminal:

```sh
hiccup serve &                             # a headless instance
hiccup proxy start                         # start its proxy
hiccup proxy status                        # add --json for scripts
hiccup proxy stop
hiccup instance stop
```

A `--foreground` proxy can be controlled the same way while it runs.

Hold requests to inspect, edit, forward or drop them:

```sh
hiccup intercept on --host '*.example.com' --method POST
hiccup intercept list                      # held messages and their IDs
hiccup intercept show 1 --raw > req.http
hiccup intercept edit 1 --file req.http    # sent exactly as edited; or edit 1 to open $EDITOR
hiccup intercept drop 2
hiccup intercept off                       # forwards whatever is still held
```

Define what you are testing, and hold only that:

```sh
hiccup scope add --protocol https --host '*.example.com'
hiccup scope add --exclude --path '^/logout'
hiccup scope test https://app.example.com/login   # in scope
hiccup intercept on --in-scope
```

Record history in a project file, and search it:

```sh
hiccup --project acme.hiccup serve &
hiccup proxy start
hiccup history list --host app.example.com --status 500
hiccup history show 42 --response > response.http   # the exact bytes
hiccup history export > acme.jsonl                  # every exchange, in full
```

Watch traffic live, as text or one JSON object per line:

```sh
hiccup events
hiccup --json events --filter exchange | jq .
```

To use a browser, [install the Hiccup CA](docs/ca.md) and set `127.0.0.1:8080` as its HTTP and HTTPS proxy. Use `--tls-passthrough` for hosts that should not be decrypted. The proxy forwards, intercepts and records traffic; the Repeater is next on the [roadmap](ROADMAP.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup on Linux, macOS and Windows.

## Documentation

- [Roadmap & milestones](ROADMAP.md)
- [Installing the Hiccup CA](docs/ca.md)
- [Control API reference](docs/control-api.md)
- [Architecture overview](docs/architecture.md)
- [Architecture decision records](docs/adr/)
- [Releasing](docs/releasing.md)

## License

Hiccup is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
