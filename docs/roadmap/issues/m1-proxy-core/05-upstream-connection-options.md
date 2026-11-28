# Upstream connection options

labels: type:feature, area:tls

## Goal

Control how Hiccup connects to target servers.

## Tasks

- [ ] Upstream TLS verification on or off (default: on; turning it off, for targets with self-signed or invalid certificates, shows a visible warning)
- [ ] SNI override, minimum/maximum TLS version, optional client certificates
- [ ] Connect/read timeouts; DNS overrides (hosts map)

## Acceptance criteria

- [ ] Each option is covered by an integration test and exposed in the CLI
