# Changelog, versioning and release process

labels: type:chore, area:release

## Goal

Make releases predictable and traceable.

## Tasks

- [ ] `CHANGELOG.md` following Keep a Changelog
- [ ] SemVer policy (pre-1.0: minor versions may break; this applies to the CLI `--json` output and the control API too)
- [ ] Release workflow skeleton: tag → build artifacts for 3 OSes → GitHub Release with checksums
- [ ] Evaluate `release-plz` or `cargo-dist` and record the decision

## Acceptance criteria

- [ ] A dry-run release produces CLI binaries for Linux, macOS and Windows
