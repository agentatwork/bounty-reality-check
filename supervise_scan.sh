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
#   1. OOM/silent kill with no error at all -- looks identical to "still running"
#   2. an uncatchable assertion thrown from a socket event deep in the HTTP parser
#
# Three things changed after the first 200k pass, all of them for the second one:
#
#   The PID file is derived from OUT, not hard-coded. It used to be /tmp/stxt.pid for every run,
#   so starting the www pass while the apex pass was still finishing would have overwritten the
#   first run's PID file, and anything watching that file would have silently switched to
#   following the wrong process -- reporting the pass that had just started as the progress of
#   the one it was actually waiting for.
#
#   A restart that makes no progress is a different event from a recycle. Recycling on the RSS
#   cap is normal and happened six times in the apex pass. A scanner that starts and dies without
#   appending a single record is a crash loop -- an empty or malformed list, a missing file, a
#   syntax error -- and the old loop would have burned all 40 restarts on it in about two minutes
#   and then reported "GIVING UP after 40 restarts", which reads like the network beat us rather
#   than like the list argument being wrong.
#
#   Record counts go through count(), which is 0 when OUT does not exist yet. The www pass starts
#   with no output file at all, and `wc -l` on a missing path writes an error to the log and
#   yields an empty string, so the exit line would have read `records=` at exactly the moment the
#   number mattered.
set -u

LIST="${1:?usage: supervise_scan.sh <list.csv> <out.jsonl> <log> [conc]}"
OUT="${2:?}"
LOG="${3:?}"
CONC="${4:-32}"
RSS_CAP_MB=650          # leave room on a ~1.9GB box that also runs this shell
MAX_RESTARTS=40
MAX_STALLED=3           # consecutive restarts that appended nothing before calling it a loop

PIDFILE="/tmp/$(basename "$OUT" .jsonl).pid"
# `wc -l < missing` returns 0 via the ||, but bash reports the failed REDIRECT on its own stderr
# before wc ever runs, and the supervisor's stderr is not the log -- under nohup that line goes
# somewhere nobody reads. Test for the file instead of catching the failure.
count() { [ -f "$OUT" ] && wc -l < "$OUT" || echo 0; }

cd "$(dirname "$0")" || exit 1
restarts=0
stalled=0

echo "SUPERVISOR: list=$LIST out=$OUT pidfile=$PIDFILE conc=$CONC" >> "$LOG"

while :; do
  if grep -q SCAN_DONE "$LOG" 2>/dev/null; then
    echo "SUPERVISOR: SCAN_DONE present, nothing to do" >> "$LOG"
    break
  fi
  if [ "$restarts" -ge "$MAX_RESTARTS" ]; then
    echo "SUPERVISOR: GIVING UP after $restarts restarts at $(count) records" >> "$LOG"
    break
  fi
  if [ "$stalled" -ge "$MAX_STALLED" ]; then
    echo "SUPERVISOR: GIVING UP -- $stalled restarts in a row appended no records at $(count)." \
         "That is a crash loop, not memory pressure; check the list argument." >> "$LOG"
    break
  fi

  before=$(count)
  node --max-old-space-size=512 scan_securitytxt.js "$LIST" "$OUT" "$CONC" >> "$LOG" 2>&1 &
  pid=$!
  echo "$pid" > "$PIDFILE"
  echo "SUPERVISOR: started pid=$pid (restart #$restarts) at $before records" >> "$LOG"

  # Watch it. Kill it politely if RSS crosses the cap -- a clean SIGTERM after a flushed write
  # is far better than the kernel picking the victim.
  while [ -d "/proc/$pid" ]; do
    sleep 20
    rss=$(awk '/VmRSS/{print int($2/1024)}' "/proc/$pid/status" 2>/dev/null)
    [ -z "$rss" ] && break
    if [ "$rss" -gt "$RSS_CAP_MB" ]; then
      echo "SUPERVISOR: rss=${rss}MB over ${RSS_CAP_MB}MB cap -- recycling pid=$pid at $(count) records" >> "$LOG"
      kill "$pid" 2>/dev/null
      sleep 5
      kill -9 "$pid" 2>/dev/null
      break
    fi
  done
  wait "$pid" 2>/dev/null

  grep -q SCAN_DONE "$LOG" 2>/dev/null && break
  if [ "$(count)" -gt "$before" ]; then stalled=0; else stalled=$((stalled + 1)); fi
  restarts=$((restarts + 1))
  sleep 3
done

echo "SUPERVISOR_EXIT records=$(count) restarts=$restarts" >> "$LOG"
