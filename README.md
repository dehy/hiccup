# Hiccup

An open source, cross-platform web security testing toolkit written in Rust. Hiccup is an intercepting HTTP(S) proxy with a Repeater and native desktop interfaces for Linux, macOS and Windows.

> **Status:** pre-alpha, in planning. There is no usable code yet. See the [roadmap](ROADMAP.md).

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
hiccup proxy start --foreground            # listens on 127.0.0.1:8080
curl -x http://127.0.0.1:8080 http://example.com/

# HTTPS is decrypted with a CA generated for your installation:
hiccup ca export -o hiccup.pem
curl -x http://127.0.0.1:8080 --cacert hiccup.pem https://example.com/
```

To use a browser, [install the Hiccup CA](docs/ca.md) and set `127.0.0.1:8080` as its HTTP and HTTPS proxy. Use `--tls-passthrough` for hosts that should not be decrypted. The proxy only forwards traffic and logs it for now; history, interception and the Repeater are next on the [roadmap](ROADMAP.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup on Linux, macOS and Windows.

## Documentation

- [Roadmap & milestones](ROADMAP.md)
- [Installing the Hiccup CA](docs/ca.md)
- [Architecture overview](docs/architecture.md)
- [Architecture decision records](docs/adr/)
- [Releasing](docs/releasing.md)

## License

Hiccup is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
