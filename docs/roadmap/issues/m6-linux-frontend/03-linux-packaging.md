# Linux packaging

labels: type:chore, area:release, platform:linux

## Goal

Distribute the app and CLI on Linux.

## Tasks

- [ ] Flatpak manifest (Flathub-ready), AppImage, `.deb` and `.rpm` (cargo-deb / cargo-generate-rpm)
- [ ] Release workflow attaches the artifacts

## Acceptance criteria

- [ ] Artifacts install and run on current Debian/Ubuntu, Fedora and Kali; v0.3.0 released
