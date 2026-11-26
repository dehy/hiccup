# Message viewer and editor

labels: type:feature, area:ui, platform:linux

## Goal

Inspect and edit HTTP messages.

## Tasks

- [ ] Raw view (GtkSourceView, with HTTP syntax highlighting), headers table, hex view
- [ ] Read-only and editable modes; the editor keeps exact bytes, including CR/LF and non-UTF-8

## Acceptance criteria

- [ ] Editing then sending keeps bytes exactly (test via the core)
