#!/usr/bin/env bash
# Build the spec-007 US1 fixture: a webroot that exists ONLY inside another process's root view,
# /proc/<pid>/root -- what a responder sees from a Kubernetes debug container sharing the pod's
# process namespace. An unprivileged user+mount namespace (`unshare -Urm`) mounts a tmpfs over /mnt
# and /srv and writes known-detected content there; from the caller's namespace the same paths do not
# exist, and the only way to reach the files is through /proc/<pid>/root/...
#
# The Go tests in internal/discover and cmd/diskprobe build this condition themselves through
# internal/testfixture. This script exists for the two jobs the tests cannot do:
#
#   1. reproducing the defect by hand against a RELEASE binary (ours or the incumbent's);
#   2. letting a responder confirm on their own host that a build reads a process-root view.
#
# Usage:
#   scripts/linux/nsfixture.sh <dir>          start; writes <dir>/pid and prints the paths to scan
#   scripts/linux/nsfixture.sh --stop <dir>   tear the namespace down
#
# The content is benign-inert: it is a webshell by SHAPE -- a request parameter reaching an exec
# sink -- which is what the detectors match. Nothing here runs anything.
set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

if [ "${1:-}" = "--stop" ]; then
  [ $# -eq 2 ] || usage
  if [ -f "$2/pid" ]; then kill "$(cat "$2/pid")" 2>/dev/null || true; rm -f "$2/pid"; echo "stopped"; fi
  exit 0
fi
[ $# -eq 1 ] || usage
DIR="$1"
mkdir -p "$DIR"
HERE="$(cd "$(dirname "$0")" && pwd)"
"$HERE/check-fixture-fs.sh" "$DIR" >/dev/null || { echo "FAIL: $DIR cannot express the fixture (see check-fixture-fs.sh)" >&2; exit 1; }
command -v unshare >/dev/null || { echo "FAIL: unshare(1) is not installed" >&2; exit 1; }
unshare -Urm true 2>/dev/null || { echo "FAIL: unprivileged user+mount namespaces are refused on this host" >&2; exit 1; }
[ -f "$DIR/pid" ] && kill -0 "$(cat "$DIR/pid")" 2>/dev/null && { echo "already running (pid $(cat "$DIR/pid")); --stop it first" >&2; exit 1; }

# Stage: the files, laid out as they will appear inside the namespace. Two locations:
#   /mnt/srv/www  -- reachable ONLY by naming it (--path), no discovery mechanism knows it
#   /srv/www      -- a conventional location, so --root discovery finds it unaided
STAGE="$DIR/stage"; rm -rf "$STAGE"; mkdir -p "$STAGE/mnt/srv/www" "$STAGE/srv/www"
for root in "$STAGE/mnt/srv/www" "$STAGE/srv/www"; do
  printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$root/shell.php"
  printf '%s' '<?php eval(base64_decode("PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==")); ?>' > "$root/encoded.php"
  printf '%s\n' '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("c")); %>' > "$root/shell.jsp"
  printf '%s' 'plain text, nothing to see' > "$root/readme.txt"
  ln -s shell.php "$root/link.php"   # a same-view symlink: the disclosed residual (spec 007 R1) is COUNTED here
done

LOG="$DIR/ns.log"; : > "$LOG"
setsid unshare -Urm -- bash -c '
  set -e
  mount -t tmpfs none /mnt && cp -a "'"$STAGE"'/mnt/." /mnt/
  mount -t tmpfs none /srv && cp -a "'"$STAGE"'/srv/." /srv/
  echo READY
  exec sleep 86400
' > "$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 50); do grep -q READY "$LOG" 2>/dev/null && break; sleep 0.1; done
grep -q READY "$LOG" || { echo "FAIL: namespace did not become ready: $(cat "$LOG")" >&2; kill "$PID" 2>/dev/null || true; exit 1; }
echo "$PID" > "$DIR/pid"

echo "namespace pid: $PID"
echo "explicit-path form:   --path /proc/$PID/root/mnt/srv/www"
echo "discovery form:       --root /proc/$PID/root        (finds /srv/www by convention, served as /srv/www)"
echo "control (must NOT exist here): /mnt/srv/www -> $([ -e /mnt/srv/www ] && echo 'EXISTS -- fixture is not isolated' || echo 'absent, as required')"
echo "files visible through the view: $(ls "/proc/$PID/root/mnt/srv/www" | tr '\n' ' ')"
echo "stop with: $0 --stop $DIR"
