#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Create GitHub labels, milestones and issues from docs/roadmap/issues/.
#
# Layout:
#   docs/roadmap/issues/<slug>/_milestone.md   "# <Milestone title>" + description
#   docs/roadmap/issues/<slug>/NN-*.md         "# <Issue title>", "labels: a, b", body
#
# The script is idempotent: existing labels, milestones and issues (matched
# by exact title) are skipped.
#
# Usage: scripts/github-bootstrap.sh [--dry-run] [--repo OWNER/NAME]

set -euo pipefail

DRY_RUN=0
REPO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --repo) REPO="${2:?--repo needs OWNER/NAME}"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISSUES_DIR="$ROOT/docs/roadmap/issues"

if [[ $DRY_RUN -eq 0 ]]; then
  command -v gh >/dev/null || { echo "error: gh CLI not found" >&2; exit 1; }
  if [[ -z "$REPO" ]]; then
    REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
  fi
  echo "Target repository: $REPO"
fi

title_of()  { sed -n '1s/^# //p' "$1"; }
labels_of() { sed -n 's/^labels: //p' "$1" | head -n1; }
# Body = everything after the title and labels lines, leading blank lines trimmed.
body_of()   { sed -e '1d' -e '/^labels: /d' "$1" | sed '/./,$!d'; }

label_color() {
  case "$1" in
    type:*)     echo "1d76db" ;;
    area:*)     echo "0e8a16" ;;
    platform:*) echo "5319e7" ;;
    *)          echo "c5def5" ;;
  esac
}

run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

# ---------------------------------------------------------------- labels
mapfile -t LABELS < <(
  { for f in "$ISSUES_DIR"/*/[0-9]*.md; do labels_of "$f" | tr ',' '\n'; done
    printf "%s\n" type:roadmap type:bug; } | sed 's/^ *//; s/ *$//' | grep -v '^$' | sort -u
)

existing_labels=""
existing_milestones=""
existing_issues=""
if [[ $DRY_RUN -eq 0 ]]; then
  existing_labels="$(gh label list --repo "$REPO" --limit 1000 --json name --jq '.[].name')"
  existing_milestones="$(gh api --paginate "repos/$REPO/milestones?state=all&per_page=100" --jq '.[].title')"
  existing_issues="$(gh issue list --repo "$REPO" --state all --limit 5000 --json title --jq '.[].title')"
fi

contains() { grep -Fxq -- "$2" <<<"$1"; }

echo "== Labels (${#LABELS[@]})"
for l in "${LABELS[@]}"; do
  if contains "$existing_labels" "$l"; then echo "skip label: $l"; continue; fi
  run gh label create "$l" --repo "${REPO:-OWNER/NAME}" --color "$(label_color "$l")"
done

# ---------------------------------------------------------------- milestones + issues
for dir in "$ISSUES_DIR"/*/; do
  mfile="$dir/_milestone.md"
  [[ -f "$mfile" ]] || { echo "error: missing $mfile" >&2; exit 1; }
  mtitle="$(title_of "$mfile")"
  mdesc="$(body_of "$mfile")"

  echo "== Milestone: $mtitle"
  if contains "$existing_milestones" "$mtitle"; then
    echo "skip milestone: $mtitle"
  else
    run gh api "repos/${REPO:-OWNER/NAME}/milestones" -f title="$mtitle" -f description="$mdesc" --silent
  fi

  for f in "$dir"[0-9]*.md; do
    ititle="$(title_of "$f")"
    ilabels="$(labels_of "$f" | sed 's/, */,/g')"
    [[ -n "$ititle" && -n "$ilabels" ]] || { echo "error: $f lacks title or labels" >&2; exit 1; }
    if contains "$existing_issues" "$ititle"; then echo "skip issue: $ititle"; continue; fi
    if [[ $DRY_RUN -eq 1 ]]; then
      echo "[dry-run] issue: \"$ititle\" -> \"$mtitle\" [$ilabels]"
    else
      body_of "$f" | gh issue create --repo "$REPO" --title "$ititle" \
        --milestone "$mtitle" --label "$ilabels" --body-file -
    fi
  done
done

echo "Done."
