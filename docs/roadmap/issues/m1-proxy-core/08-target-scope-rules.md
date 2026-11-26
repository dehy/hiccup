# Target scope rules

labels: type:feature, area:core

## Goal

Let users define what is in scope.

## Tasks

- [ ] Include/exclude rules on protocol, host (glob/regex), port and path
- [ ] Scope is used by history filtering, intercept rules and, later, the repeater redirect policy

## Acceptance criteria

- [ ] `hiccup scope add|remove|list|test <url>` works
