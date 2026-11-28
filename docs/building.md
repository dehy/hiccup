# Building from source

Hiccup has no release binaries yet, so you build it yourself. It takes a Rust toolchain, a C toolchain and a few minutes. The result is one binary, `hiccup`, with nothing else to install next to it: SQLite and the TLS stack are compiled in.

## Requirements

Install Rust with [rustup](https://rustup.rs). The repository's `rust-toolchain.toml` selects the stable channel, so rustup downloads it on the first build. The minimum supported version is the `rust-version` in [`Cargo.toml`](../Cargo.toml).

You also need a C toolchain, for the cryptography and SQLite code:

| OS      | C toolchain |
|---------|-------------|
| macOS   | Xcode Command Line Tools (`xcode-select --install`) |
| Windows | Visual Studio Build Tools with the "Desktop development with C++" workload |
| Linux   | `build-essential` on Debian, Ubuntu and Kali, `gcc` on Fedora |

## Build

```sh
git clone https://github.com/dehy/hiccup.git
cd hiccup
cargo build --release --locked -p hiccup-cli
./target/release/hiccup --version
```

The binary is `target/release/hiccup` (`hiccup.exe` on Windows). `--locked` builds with the exact dependency versions in `Cargo.lock`, as the release workflow does.

## Install

To put `hiccup` on your `PATH`, install it with Cargo:

```sh
cargo install --locked --path crates/hiccup-cli
```

This copies the binary to `~/.cargo/bin`, which rustup already added to your `PATH`. Copying `target/release/hiccup` anywhere on your `PATH` works too. [The `hiccup` CLI](cli.md) shows how to install shell completions and man pages.

## Update

```sh
git pull
cargo install --locked --path crates/hiccup-cli
```

Hiccup is pre-alpha: read the [changelog](../CHANGELOG.md) before you update, because commands and file formats can still change.

## Uninstall

```sh
cargo uninstall hiccup-cli
```

This removes the binary only. The CA and `config.json` stay in Hiccup's data directory, listed in [Installing the CA](ca.md), along with how to remove the CA from the stores where you installed it.

## Build for another architecture

Add the target with rustup and pass it to Cargo. For example, on an Apple silicon Mac:

```sh
rustup target add x86_64-apple-darwin
cargo build --release --locked -p hiccup-cli --target x86_64-apple-darwin
```

The binary is then in `target/x86_64-apple-darwin/release/`. The release workflow builds these targets:

| OS      | Targets |
|---------|---------|
| macOS   | `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| Windows | `aarch64-pc-windows-msvc`, `x86_64-pc-windows-msvc` |
| Linux   | `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu` |

Building for another OS needs that OS's linker and C toolchain, so build on the OS you are targeting.

## Check your build

```sh
cargo test --workspace
```

To work on Hiccup itself, [CONTRIBUTING.md](../CONTRIBUTING.md) lists the checks CI runs and how to fuzz the HTTP parser.
