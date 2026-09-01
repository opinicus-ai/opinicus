#!/usr/bin/env bash
#
# Snapshot and verify the Rohrpost store (.rohrpost).
#
# Why this exists: on 2026-08-31 an uncommitted, open ticket and one log
# event existed in the working tree and were gone an hour later, during a
# review window that was supposed to be read-only; the cause could not be
# established (docs/PROJECT-REVIEW.md section 2.5, docs/DECISIONS.md
# 2026-09-01). From that day on, every agent workflow that runs against this
# repository starts by fingerprinting the store, and ends by proving the
# fingerprint still holds — read-only means byte-identical.
#
# Usage:
#   scripts/rohrpost-snapshot.sh            write a snapshot and print the hashes
#   scripts/rohrpost-snapshot.sh --check    compare the store against the newest
#                                           snapshot; non-zero exit on drift
#
# A snapshot records: the commit, the `git status --porcelain` lines of
# .rohrpost (the snapshot directory itself filtered out), and the sha256 of
# the store's two tracked files. Snapshots are local working-state
# fingerprints, not history; they live gitignored under .rohrpost/snapshots/.
#
# Exit codes: 0 = snapshot written / no drift; 1 = drift detected;
# 2 = usage or environment error.
#
# Run --check after any workflow that was supposed to leave the store
# untouched. A workflow that legitimately changed the store (rp new,
# rp comment, ...) does not check against the old snapshot; it finishes by
# committing the store and taking a fresh snapshot.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROHRPOST="$ROOT/.rohrpost"
SNAPDIR="$ROHRPOST/snapshots"
LOG="$ROHRPOST/log.jsonl"
TICKETS="$ROHRPOST/tickets.jsonl"

die() { printf 'rohrpost-snapshot: %s\n' "$1" >&2; exit 2; }

[ -f "$LOG" ] || die "missing $LOG (run inside the repository)"
[ -f "$TICKETS" ] || die "missing $TICKETS (run inside the repository)"
command -v git >/dev/null 2>&1 || die "git not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository"

hash_log() { sha256sum "$LOG" | cut -d' ' -f1; }
hash_tickets() { sha256sum "$TICKETS" | cut -d' ' -f1; }

# The porcelain lines that describe the store itself. Everything else in
# `git status` may legitimately change during a workflow.
rohrpost_status() {
    git -C "$ROOT" status --porcelain -- .rohrpost | grep -v '/snapshots/' || true
}

newest_snapshot() {
    local names
    names="$(ls -1 "$SNAPDIR" 2>/dev/null || true)"
    if [ -n "$names" ]; then
        printf '%s\n' "$names" \
            | grep -E '^[0-9]{8}T[0-9]{6}Z\.txt$' | sort | tail -1 || true
    fi
}

stored() { # $1 = snapshot file, $2 = key; prints the stored value of key
    awk -F': ' -v key="$2" '$1 == key { print $2 }' "$1"
}

REV="$(git -C "$ROOT" rev-parse HEAD)"

if [ "${1:-}" = "--check" ]; then
    SNAP="$(newest_snapshot)"
    if [ -z "${SNAP:-}" ]; then
        die "no snapshot to check against; take one first"
    fi
    FILE="$SNAPDIR/$SNAP"

    DRIFT=0
    for name in log.jsonl tickets.jsonl; do
        THEN="$(stored "$FILE" "sha256 .rohrpost/$name")"
        [ -n "$THEN" ] || die "snapshot $SNAP is malformed (no hash for $name)"
        case "$name" in
        log.jsonl) NOW="$(hash_log)" ;;
        tickets.jsonl) NOW="$(hash_tickets)" ;;
        esac
        if [ "$NOW" != "$THEN" ]; then
            printf 'drift: .rohrpost/%s changed since %s\n  snapshot: %s\n  now:      %s\n' \
                "$name" "$SNAP" "$THEN" "$NOW" >&2
            DRIFT=1
        fi
    done

    THEN_STATUS="$(sed -n 's/^status //p' "$FILE")"
    NOW_STATUS="$(rohrpost_status)"
    if [ "$NOW_STATUS" != "$THEN_STATUS" ]; then
        printf 'drift: git status of .rohrpost changed since %s\n  snapshot:\n%s\n  now:\n%s\n' \
            "$SNAP" "$(printf '%s\n' "$THEN_STATUS" | sed 's/^/    /')" \
            "$(printf '%s\n' "$NOW_STATUS" | sed 's/^/    /')" >&2
        DRIFT=1
    fi

    if [ "$DRIFT" -eq 0 ]; then
        printf 'no drift against %s (rev %s)\n' "$SNAP" "$REV"
    fi
    exit "$DRIFT"
elif [ -n "${1:-}" ]; then
    die "usage: $0 [--check]"
fi

# Default: write a snapshot.
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$SNAPDIR"
FILE="$SNAPDIR/$STAMP.txt"
if [ -e "$FILE" ]; then
    die "snapshot $STAMP already exists; wait a second and retry"
fi

{
    printf 'timestamp: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'git-rev: %s\n' "$REV"
    printf '# git status --porcelain -- .rohrpost (snapshots/ filtered)\n'
    rohrpost_status | sed 's/^/status /'
    printf 'sha256 .rohrpost/log.jsonl: %s\n' "$(hash_log)"
    printf 'sha256 .rohrpost/tickets.jsonl: %s\n' "$(hash_tickets)"
} > "$FILE"

printf 'snapshot: %s\n' "$FILE"
printf 'sha256 .rohrpost/log.jsonl: %s\n' "$(hash_log)"
printf 'sha256 .rohrpost/tickets.jsonl: %s\n' "$(hash_tickets)"
