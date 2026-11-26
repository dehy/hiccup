# Event stream API

labels: type:feature, area:control

## Goal

Push live events to frontends and the CLI.

## Tasks

- [ ] Events: request captured, response captured, intercept pending/resolved, listener state, errors
- [ ] Backpressure-safe broadcast (bounded channels; slow subscribers are dropped and told to resync)
- [ ] `hiccup events [--json] [--filter …]` streams to stdout

## Acceptance criteria

- [ ] `hiccup events --json | jq` shows traffic live while curl uses the proxy
