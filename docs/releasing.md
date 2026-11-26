# Releasing

## Versioning

Hiccup follows [SemVer](https://semver.org/). All workspace crates share one version (`[workspace.package] version`).

The public surface covered by SemVer:

- the `hiccup` CLI commands, flags and exit codes;
- the CLI's `--json` output schema;
- the control API (JSON-RPC methods and notifications);
- the project file format (newer versions must be able to open older projects).

Before 1.0.0, a **minor** bump (`0.x → 0.(x+1)`) may break any of these, and a **patch** bump may not.

## Release checklist

1. Make sure `main` is green.
2. Bump `version` in the root `Cargo.toml` and run `cargo check` to refresh `Cargo.lock`.
3. In `CHANGELOG.md`, rename `Unreleased` to the new version and date, and add a new empty `Unreleased` section and the compare links.
4. Open a PR `chore(release): vX.Y.Z`, and merge it.
5. Tag the merge commit and push the tag:
   ```sh
   git tag -s vX.Y.Z -m "Hiccup vX.Y.Z"
   git push origin vX.Y.Z
   ```
6. The [Release workflow](../.github/workflows/release.yml) builds the archives for all targets, generates `SHA256SUMS` and creates a **draft** GitHub Release.
7. Review the draft, paste the changelog section into the release notes, and publish it.

To test the pipeline without releasing, run the *Release* workflow manually (*Actions → Release → Run workflow*). It builds and uploads artifacts without creating a release.

## Tooling decision

See [ADR 0005](adr/0005-release-tooling.md).
