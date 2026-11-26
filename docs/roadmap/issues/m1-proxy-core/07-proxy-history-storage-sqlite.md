# Proxy history storage (SQLite)

labels: type:feature, area:store

## Goal

Persist every proxied exchange for later inspection.

## Tasks

- [ ] `hiccup-store` built on rusqlite with schema migrations
- [ ] A project file (`.hiccup`) holding history: raw request/response, timings, TLS info, edited flag
- [ ] Paginated, filtered queries (host, method, status, MIME, search text, in-scope)
- [ ] Large bodies stored efficiently (blob table, optional compression)

## Acceptance criteria

- [ ] 10k exchanges inserted and queried with p95 < 50 ms on a laptop (benchmark)
- [ ] History survives a restart
