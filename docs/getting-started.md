# Getting started

Hiccup is pre-alpha. There are no release binaries yet, so you build it from source. The headless proxy and its history work from the CLI on macOS, Windows and Linux. The Repeater and the desktop apps are on the [roadmap](../ROADMAP.md).

## Install

With [Rust](https://rustup.rs) and a C toolchain installed:

```sh
git clone https://github.com/dehy/hiccup.git
cd hiccup
cargo install --locked --path crates/hiccup-cli
hiccup --version
```

[Building from source](building.md) covers the requirements for each OS, updating, uninstalling and other architectures.

## Proxy your first request

```sh
hiccup proxy start --foreground            # listens on 127.0.0.1:8080, until Ctrl+C
```

In another terminal:

```sh
curl -x http://127.0.0.1:8080 http://example.com/
```

Use `--listen` to choose another address. Hiccup warns you when it listens beyond loopback, because anyone who can reach the proxy can use it.

## Decrypt HTTPS

Hiccup decrypts HTTPS with certificates signed by a certificate authority (CA) generated for your installation. Export it and tell the client to trust it:

```sh
hiccup ca export -o hiccup.pem
curl -x http://127.0.0.1:8080 --cacert hiccup.pem https://example.com/
```

To use a browser, [install the Hiccup CA](ca.md) and set `127.0.0.1:8080` as its HTTP and HTTPS proxy. Use `--tls-passthrough` for hosts that should not be decrypted, such as clients that pin certificates.

## Run in the background

Every running Hiccup is an instance that other `hiccup` commands control over a local socket. Start a headless one and drive it from any terminal:

```sh
hiccup serve &                             # a headless instance
hiccup proxy start                         # start its proxy
hiccup proxy status                        # add --json for scripts
hiccup proxy stop
hiccup instance stop
```

A `--foreground` proxy can be controlled the same way while it runs. `hiccup instance list` shows the running instances, and `--instance NAME` picks one when there are several.

## Hold and edit requests

```sh
hiccup intercept on --host '*.example.com' --method POST
hiccup intercept list                      # held messages and their IDs
hiccup intercept show 1 --raw > req.http
hiccup intercept edit 1 --file req.http    # sent exactly as edited; or edit 1 to open $EDITOR
hiccup intercept drop 2
hiccup intercept off                       # forwards whatever is still held
```

An edited message is sent with exactly the bytes you wrote: Hiccup doesn't fix the `Content-Length`, the header case or the line endings for you.

## Define the scope

Say what you are testing, then hold only that:

```sh
hiccup scope add --protocol https --host '*.example.com'
hiccup scope add --exclude --path '^/logout'
hiccup scope test https://app.example.com/login   # in scope
hiccup intercept on --in-scope
```

## Record and search history

Give an instance a project file, and it records every exchange with its exact bytes:

```sh
hiccup --project acme.hiccup serve &
hiccup proxy start
hiccup history list --host app.example.com --status 500
hiccup history show 42 --response > response.http   # the exact bytes
hiccup history export > acme.jsonl                  # every exchange, in full
```

## Watch traffic live

```sh
hiccup events
hiccup --json events --filter exchange | jq .
```

With `--json`, every command prints JSON for scripts, and `events` prints one JSON object per line.

## Next

- [The `hiccup` CLI](cli.md): global flags, exit codes, saved defaults (`hiccup config`), shell completions and man pages.
- [The control API](control-api.md): the same operations, for programs that talk to an instance directly.
