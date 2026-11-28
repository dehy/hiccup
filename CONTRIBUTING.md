# Contributing to Hiccup

Thanks for your interest in Hiccup! This document explains how to set up a development environment and how changes get merged.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md). For security issues, read [SECURITY.md](SECURITY.md) and **do not** open a public issue.

## Ways to contribute

- Report bugs and request features with the [issue forms](https://github.com/dehy/hiccup/issues/new/choose).
- Pick an issue from the current [milestone](ROADMAP.md). Comment on it first, so we can avoid duplicate work.
- Improve the documentation.
- Propose roadmap or architecture changes. Open a `type:roadmap` issue; an architecture change also needs an ADR (see below).

## Development setup

You need a Rust toolchain installed with [rustup](https://rustup.rs). The repository's `rust-toolchain.toml` selects the right toolchain and components automatically.

| OS      | Extra requirements |
|---------|--------------------|
| Linux   | A C toolchain (`build-essential` on Debian/Ubuntu/Kali, `gcc` on Fedora) |
| macOS   | Xcode Command Line Tools (`xcode-select --install`) |
| Windows | Visual Studio Build Tools with the "Desktop development with C++" workload |

The native frontends (from M4 onward) will add per-OS requirements (Xcode, Windows App SDK, GTK4/libadwaita). They will be documented here.

```sh
git clone https://github.com/dehy/hiccup.git
cd hiccup
cargo build
cargo test --workspace
cargo run -p hiccup-cli -- --help
```

Optional tools used by CI:

```sh
cargo install --locked cargo-deny cargo-llvm-cov
```

## Before you open a pull request

Run the same checks as CI:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps          # with RUSTDOCFLAGS="-D warnings"
cargo deny check
```

Also check the following:

- **Tests:** new behaviour has tests, and bug fixes have a regression test.
- **CLI parity:** every user-visible feature must be reachable from the `hiccup` CLI ([ADR 0004](docs/adr/0004-cli-control-plane.md)).
- **Wire fidelity:** never normalize HTTP messages silently ([ADR 0003](docs/adr/0003-raw-http-fidelity.md)).
- **Changelog:** add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- **License header:** every new source file starts with `// SPDX-License-Identifier: AGPL-3.0-or-later`.

## Fuzzing

The HTTP codec has [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) targets in `fuzz/`. They need a nightly toolchain:

```sh
rustup toolchain install nightly
cargo install --locked cargo-fuzz
cd fuzz && cargo +nightly fuzz run parse_request -- -max_total_time=60
```

If you find a crash, add the input to the unit tests as a regression case. If it could be security-relevant, report it privately (see [SECURITY.md](SECURITY.md)).

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <summary in imperative mood>

<optional body explaining what and why>

Signed-off-by: Your Name <you@example.com>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `revert`. Scopes usually name a crate or area (`proxy`, `http`, `cli`, `tls`, …). Mark breaking changes with `!` (`feat(cli)!: …`) or with a `BREAKING CHANGE:` footer.

## Developer Certificate of Origin (DCO)

Hiccup does not use a CLA. Instead, every commit must be signed off to certify that you have the right to submit it under the project's license ([AGPL-3.0-or-later](LICENSE)), as described in the [Developer Certificate of Origin 1.1](https://developercertificate.org/).

Sign off by committing with `-s`:

```sh
git commit -s -m "fix(http): handle empty chunk extensions"
```

A CI check rejects pull requests that contain commits without a sign-off. To fix older commits, run `git rebase --signoff main`. Dependabot cannot sign off, so its own commits in the pull requests it opens are exempt.

## Pull request workflow

1. Fork the repository and create a branch from `main`, for example `feat/intercept-rules`.
2. Keep PRs focused. Unrelated refactors go in separate PRs.
3. Fill in the PR template, and link the issue (`Closes #123`).
4. CI must be green on Linux, macOS and Windows.
5. Merging needs at least one maintainer approval. We squash-merge, and the PR title becomes the commit message, so it must follow Conventional Commits too.

## Architecture Decision Records

Significant design decisions are recorded in [`docs/adr/`](docs/adr/). To propose a new one:

1. Copy the format of an existing ADR into `docs/adr/NNNN-short-title.md` (next free number).
2. Set the status to `Proposed`, and open a PR for discussion.
3. When it is accepted, set the status to `Accepted`. Never rewrite an accepted ADR: supersede it with a new one.

## Rust version policy (MSRV)

The minimum supported Rust version is the `rust-version` in [`Cargo.toml`](Cargo.toml), and CI checks it. Our target is to support **the latest stable Rust minus two minor releases**. Raising the MSRV is allowed in any minor release and is noted in the changelog. Day-to-day development uses the latest stable toolchain (`rust-toolchain.toml`).

## License

By contributing, you agree that your contributions are licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
