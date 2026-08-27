#!/bin/bash
# supervise_scan.sh — run scan_securitytxt.js to completion on a box that cannot hold it.
#
#   ./supervise_scan.sh <list.csv> <out.jsonl> <log> [concurrency]
#
# The scanner is resumable (append-only JSONL + a skip-set built from the output), which makes
# restarting it free. This turns that property into a policy: restart on death, and restart
# BEFORE death when memory says it is coming.
#
# Why a restart is the fix rather than a memory leak hunt: node's fetch keeps a connection pool
# per ORIGIN, and this workload visits ~181k distinct origins exactly once each. The pool only
# grows. There is no public API to bound it (setGlobalDispatcher lives in the undici package,
# not in node's built-in copy), so the process is structurally unable to finish the list in one
# go. Restarting every RSS_CAP megabytes costs one re-read of the output file and nothing else.
#
# The two failure modes this replaces, both already observed on this run:
#   1. OOM//silent kill with no error at all -- looks identical to "still running"
#   2. an uncatchable assertion thrown from a socket event deep in the HTTP parser
set -u

LIST="${1:?usage: supervise_scan.sh <list.csv> <out.jsonl> <log> [conc]}"
OUT="${2:?}"
LOG="${3:?}"
CONC="${4:-32}"
RSS_CAP_MB=650          # leave room on a ~1.9GB box that also runs this shell
MAX_RESTARTS=40

cd "$(dirname "$0")" || exit 1
restarts=0

while :; do
  if grep -q SCAN_DONE "$LOG" 2>/dev/null; then
    echo "SUPERVISOR: SCAN_DONE present, nothing to do" >> "$LOG"
    break
  fi
  if [ "$restarts" -ge "$MAX_RESTARTS" ]; then
    echo "SUPERVISOR: GIVING UP after $restarts restarts at $(wc -l < "$OUT") records" >> "$LOG"
    break
  fi

  node --max-old-space-size=512 scan_securitytxt.js "$LIST" "$OUT" "$CONC" >> "$LOG" 2>&1 &
  pid=$!
  echo "$pid" > /tmp/stxt.pid
  echo "SUPERVISOR: started pid=$pid (restart #$restarts) at $(wc -l < "$OUT" 2>/dev/null || echo 0) records" >> "$LOG"

  # Watch it. Kill it politely if RSS crosses the cap -- a clean SIGTERM after a flushed write
  # is far better than the kernel picking the victim.
  while [ -d "/proc/$pid" ]; do
    sleep 20
    rss=$(awk '/VmRSS/{print int($2/1024)}' "/proc/$pid/status" 2>/dev/null)
    [ -z "$rss" ] && break
    if [ "$rss" -gt "$RSS_CAP_MB" ]; then
      echo "SUPERVISOR: rss=${rss}MB over ${RSS_CAP_MB}MB cap -- recycling pid=$pid at $(wc -l < "$OUT") records" >> "$LOG"
      kill "$pid" 2>/dev/null
      sleep 5
      kill -9 "$pid" 2>/dev/null
      break
    fi
  done
  wait "$pid" 2>/dev/null

  grep -q SCAN_DONE "$LOG" 2>/dev/null && break
  restarts=$((restarts + 1))
  sleep 3
done

echo "SUPERVISOR_EXIT records=$(wc -l < "$OUT") restarts=$restarts" >> "$LOG"
