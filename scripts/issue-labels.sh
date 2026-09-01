#!/usr/bin/env bash
#
# Create the issue-triage labels the report templates route to.
#
# SECURITY.md sends false-positive and false-negative reports through
# .github/ISSUE_TEMPLATE/, and both templates carry a front-matter label
# (`false-positive`, `false-negative`). GitHub silently drops a template
# label that does not exist on the repository, so the routing the security
# policy promises only works once the labels exist. This script creates
# both; `--force` makes it safe to re-run on a repository that already has
# them (it updates instead of failing).
#
# Usage (inside a checkout; gh resolves the repository from the remote):
#   scripts/issue-labels.sh
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

gh label create false-positive \
  --force \
  --color fbca04 \
  --description "A normal action was questioned, refused or stopped (interruption budget)"

gh label create false-negative \
  --force \
  --color d73a4a \
  --description "A dangerous action passed with no question, refusal or report"

gh label list --limit 100 | grep -E '^false-(positive|negative)\b'
