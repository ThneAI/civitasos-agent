#!/usr/bin/env bash
# Quick progress snapshot for an in-flight F.1.c run. Safe to run anytime.
# Usage:  ./benchmarks/f1c_status.sh   [runs_root]
set -eu
RUNS_ROOT="${1:-runs/F1c}"

if [ ! -d "$RUNS_ROOT" ]; then
    echo "no runs at $RUNS_ROOT" >&2
    exit 1
fi

echo "── F.1.c status @ $(date -u +%FT%TZ) ──────────────────────────────"
for AGENT in alpha beta gamma; do
    DIR="$(ls -dt "$RUNS_ROOT"/baseline-"${AGENT}"-*/ 2>/dev/null | head -1 || true)"
    if [ -z "$DIR" ]; then
        printf "  %-6s : (no run yet)\n" "$AGENT"
        continue
    fi
    DIR="${DIR%/}"
    DONE=$(find "$DIR/tasks" -name result.json 2>/dev/null | wc -l)
    TICKS=$(find "$DIR/raw_ticks" -name '*.csv' 2>/dev/null | wc -l)
    NEWEST=$(find "$DIR/tasks" -name result.json -printf '%T@ %p\n' 2>/dev/null \
             | sort -nr | head -1 | awk '{print $2}')
    LAST_AGE=""
    if [ -n "$NEWEST" ]; then
        LAST_TS=$(stat -c %Y "$NEWEST")
        NOW=$(date +%s)
        LAST_AGE="$(( (NOW - LAST_TS) / 60 ))m ago"
    fi
    printf "  %-6s : %2d done, %2d csv  (%s)  %s\n" \
        "$AGENT" "$DONE" "$TICKS" "$(basename "$DIR")" "$LAST_AGE"
done
echo
echo "Tail launcher log:"
LATEST_LOG=$(ls -t "$RUNS_ROOT"/launcher_*.log 2>/dev/null | head -1 || true)
if [ -n "$LATEST_LOG" ]; then
    echo "  $LATEST_LOG"
    tail -5 "$LATEST_LOG" | sed 's/^/    /'
fi
