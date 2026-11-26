# Proxy history view

labels: type:feature, area:ui, platform:linux

## Goal

Browse and filter captured traffic.

## Tasks

- [ ] Virtualized list (`GtkColumnView`) over paginated core queries
- [ ] Filter bar (host, method, status, MIME, search, scope); live updates from events
- [ ] Context menu: send to Repeater, copy as raw/curl, add host to scope

## Acceptance criteria

- [ ] Smooth scrolling with 100k items
