# CLI: proxy, intercept, history, scope and CA commands

labels: type:feature, area:cli

## Goal

Every M1 feature is reachable from the `hiccup` CLI.

## Tasks

- [ ] Built with `clap` (derive): `hiccup proxy start|stop|status`, `hiccup intercept …`, `hiccup history list|show|export`, `hiccup scope …`, `hiccup ca …`, `hiccup config get|set`
- [ ] Global flags `--json`, `--instance`, `--project`, `-v/-q`
- [ ] Documented exit codes; shell completions (bash, zsh, fish, PowerShell); man page generation

## Acceptance criteria

- [ ] A full proxy session (start, intercept, edit, forward, inspect history, export) is scripted in an e2e test on all 3 OSes
