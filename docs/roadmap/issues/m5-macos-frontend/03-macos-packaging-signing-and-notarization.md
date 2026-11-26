# macOS packaging, signing and notarization

labels: type:chore, area:release, platform:macos

## Goal

Distribute on macOS.

## Tasks

- [ ] Universal binary; codesign + notarize in CI (secrets documented); `.dmg`; Homebrew cask and a formula for the CLI

## Acceptance criteria

- [ ] A notarized `.dmg` opens without Gatekeeper warnings; v0.2.0 released
