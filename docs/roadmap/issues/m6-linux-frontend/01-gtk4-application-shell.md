# GTK4 application shell

labels: type:feature, area:ui, platform:linux

## Goal

Create the Linux app skeleton.

## Tasks

- [ ] `hiccup-gtk` crate (gtk4-rs + libadwaita); app ID, icons, `.desktop` file
- [ ] Main window with tool navigation (Proxy, Repeater, Settings); project open/new
- [ ] Embedded control server so the CLI drives the GUI live (ADR 0004)

## Acceptance criteria

- [ ] `hiccup intercept forward` from a terminal updates the open GUI
