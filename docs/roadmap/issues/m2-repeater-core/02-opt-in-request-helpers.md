# Opt-in request helpers

labels: type:feature, area:repeater

## Goal

Convenience features that never apply silently.

## Tasks

- [ ] Auto-update Content-Length (opt-in per tab, shown in the UI and CLI output)
- [ ] Redirect policy: never / always / in-scope only, with a max-hops limit
- [ ] Connection reuse toggle

## Acceptance criteria

- [ ] When the helpers are off, the bytes sent equal the editor content exactly (test)
