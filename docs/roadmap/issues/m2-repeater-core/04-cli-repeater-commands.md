# CLI: repeater commands

labels: type:feature, area:cli

## Goal

Make Repeater fully controllable from the CLI.

## Tasks

- [ ] `hiccup repeater new [--from-history ID | --file req.txt] --target https://host:443`
- [ ] `hiccup repeater send TAB [--raw-out FILE] [--json]`, `list`, `show`, `edit` (opens `$EDITOR`), `rename`, `close`, `history`
- [ ] One-shot mode without an instance: `hiccup send --target … < req.txt`

## Acceptance criteria

- [ ] The e2e test sends, edits and replays via the CLI against a running instance on all 3 OSes
