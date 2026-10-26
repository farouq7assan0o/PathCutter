#!/usr/bin/env bash
# Nightly PathCutter run: snapshot today's collection, diff against the previous snapshot, write dated reports.
# For cron or a container. Snapshots and reports hold your full AD topology - store PC_HOME like sensitive data.
#
#   Usage:  nightly.sh <collection-path> [crown-jewels.json] [telemetry.json]
#   Env:    PC_HOME   base folder for history + output (default: ./pathcutter-home)
#           PATHCUTTER  command to run (default: pathcutter, falls back to "python -m pathcutter")
#   Cron:   30 2 * * *  /opt/pathcutter/tools/nightly.sh /collect/today >> /var/log/pathcutter.log 2>&1
set -euo pipefail

collection="${1:?usage: nightly.sh <collection-path> [crown-jewels.json] [telemetry.json]}"
crown="${2:-}"
telemetry="${3:-}"
home="${PC_HOME:-./pathcutter-home}"

if [ -n "${PATHCUTTER:-}" ]; then pc=($PATHCUTTER)
elif command -v pathcutter >/dev/null 2>&1; then pc=(pathcutter)
else pc=(python -m pathcutter); fi

snapdir="$home/snapshots"; repdir="$home/reports"
mkdir -p "$snapdir" "$repdir"
date="$(date +%Y-%m-%d)"
snap="$snapdir/$date.pcsnap"

# previous snapshot = newest .pcsnap that is not today's
prev="$(ls -1t "$snapdir"/*.pcsnap 2>/dev/null | grep -v "/$date.pcsnap\$" | head -n1 || true)"

echo "[*] Snapshot -> $snap"
"${pc[@]}" snapshot "$collection" -o "$snap" --collected "$date"

analyze=("${pc[@]}" analyze "$snap" --html -o "$repdir/$date")
[ -n "$crown" ] && analyze+=(--crown-jewels "$crown")
[ -n "$telemetry" ] && analyze+=(--telemetry "$telemetry")
echo "[*] Analyze -> $repdir/$date"
"${analyze[@]}"

if [ -n "$prev" ]; then
  echo "[*] Diff $(basename "$prev") -> $date"
  "${pc[@]}" diff "$prev" "$snap" --html -o "$repdir/$date-diff"
else
  echo "[i] No previous snapshot yet; diff starts from the next run."
fi
echo "[+] Done. Reports in $repdir"
