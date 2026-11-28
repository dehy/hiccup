# SwiftUI application shell

labels: type:feature, area:ui, platform:macos

## Goal

Create the macOS app on top of the Swift package.

## Tasks

- [ ] Xcode project / SwiftPM app; app ID and icons
- [ ] Main window with sidebar navigation (Proxy, Repeater, Settings); document-based project open/new
- [ ] Embedded control server so the CLI drives the GUI live (ADR 0004)

## Acceptance criteria

- [ ] The app launches on macOS 13+ (arm64 and x86_64)
- [ ] `hiccup intercept forward` from a terminal updates the open GUI
