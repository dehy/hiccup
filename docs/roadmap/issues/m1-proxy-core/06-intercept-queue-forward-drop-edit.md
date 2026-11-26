# Intercept queue (forward / drop / edit)

labels: type:feature, area:proxy

## Goal

Pause matching messages so the user can inspect, edit, forward or drop them.

## Tasks

- [ ] Intercept toggle per direction (requests, responses)
- [ ] Intercept rules (scope, method, host, path regex)
- [ ] A queue of pending items with stable IDs; actions: forward, forward edited raw bytes, drop, forward-all
- [ ] Timeout policy for items nobody acts on

## Acceptance criteria

- [ ] `hiccup intercept list|show|forward|drop|edit` act on pending items of a running instance
- [ ] Edited bytes are sent exactly as edited (test)
