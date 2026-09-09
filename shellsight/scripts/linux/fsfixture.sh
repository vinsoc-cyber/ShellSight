#!/usr/bin/env bash
# Build the spec-002 US3 filesystem fixture: a webroot holding known-detected content beside every
# unusual file kind a hostile or merely unusual webroot can contain (data-model E6).
#
# The Go tests in cmd/diskprobe/fslinux_test.go build these conditions themselves, so this script is
# not what gates the build. It exists for the two jobs the tests cannot do:
#
#   1. reproducing the failure by hand against a RELEASE binary, ours or the incumbent's -- the
#      head-to-head needs both scanners pointed at one identical tree;
#   2. letting a responder confirm on their own host that a build survives what their webroot holds.
#
# Every case pairs the condition with a webshell placed beside it, because the failure mode being
# guarded against is loss of the WHOLE scan rather than of the offending file. Measured 2026-08-20:
# a directory containing a known webshell and one FIFO made `yr --recursive` report ZERO findings
# and never terminate, and made the probe's Perl/Python pass reach 466 MB RSS on a /dev/zero link.
#
# Usage:
#   scripts/linux/fsfixture.sh <dir>          build the fixture
#   scripts/linux/fsfixture.sh --check <dir>  only verify the filesystem is suitable
#
# The content is benign-inert: it is a webshell by SHAPE -- a request parameter reaching an exec
# sink -- which is what the detectors match. Nothing here runs anything.
set -euo pipefail

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then CHECK_ONLY=1; shift; fi
[ $# -eq 1 ] || usage
DIR="$1"

# --------------------------------------------------------------------------------------------
# Filesystem self-check (T002). Without this the fixture can be built somewhere that cannot
# represent it, and every case then passes while testing nothing.
# --------------------------------------------------------------------------------------------
check_fs() {
  local probe="$1/.fsprobe"
  rm -rf "$probe"; mkdir -p "$probe"

  # Case sensitivity. /mnt/c under WSL is v9fs and case-INSENSITIVE, so `a.PHP` and `a.php` collide
  # and the extension-case cases silently collapse into one.
  : > "$probe/CaseProbe.PHP"
  if [ -e "$probe/caseprobe.php" ]; then
    echo "FAIL: $1 is CASE-INSENSITIVE (v9fs? exFAT?). Use a native Linux filesystem." >&2
    rm -rf "$probe"; exit 1
  fi

  # Unix file kinds.
  if ! mkfifo "$probe/kindprobe" 2>/dev/null; then
    echo "FAIL: $1 does not support FIFOs, so the file-kind cases cannot be built." >&2
    rm -rf "$probe"; exit 1
  fi

  # Symlinks.
  if ! ln -s kindprobe "$probe/linkprobe" 2>/dev/null; then
    echo "FAIL: $1 does not support symlinks." >&2
    rm -rf "$probe"; exit 1
  fi

  rm -rf "$probe"
  echo "OK: $1 is case-sensitive and supports Unix file kinds and symlinks."
}

mkdir -p "$DIR"
check_fs "$DIR"
[ "$CHECK_ONLY" -eq 1 ] && exit 0

if [ "$(id -u)" = "0" ]; then
  echo "WARNING: running as root. The unreadable-file case cannot be built -- root ignores" >&2
  echo "         permission bits, so mode 000 stays readable and the case tests nothing." >&2
fi

ROOT="$DIR/www"
OUTSIDE="$DIR/outside"
rm -rf "$ROOT" "$OUTSIDE"
mkdir -p "$ROOT/sub" "$OUTSIDE"

# --------------------------------------------------------------------------------------------
# Known-detected content, one per detector path.
# --------------------------------------------------------------------------------------------
printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$ROOT/shell.php"
printf '%s\n' '#!/usr/bin/perl' 'my $CMD = $ENV{"QUERY_STRING"};' 'system($CMD);' > "$ROOT/shell.pl"
printf '%s\n' 'import cgi' 'cmd = cgi.FieldStorage().getvalue("c")' 'import os' 'os.system(cmd)' > "$ROOT/shell.py"
# A base64 layer, so the deobfuscation mirror has something to unwrap.
printf '%s' '<?php eval(base64_decode("PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==")); ?>' > "$ROOT/encoded.php"
# Same content in the sibling tree, to prove containment: nothing here may ever be reported.
printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$OUTSIDE/secret.php"

# --------------------------------------------------------------------------------------------
# The twelve conditions (E6).
# --------------------------------------------------------------------------------------------
# 1. extension-case variants -- four distinct files on a case-sensitive filesystem
for ext in php PHP Php pHp; do
  printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$ROOT/case.$ext"
done

# 2. symlink to a regular file inside the root -- content examined via the target
ln -s shell.php "$ROOT/link.php"

# 3. directory symlink escaping the root -- must not be descended
ln -s "$OUTSIDE" "$ROOT/escape"

# 3b. file symlink escaping the root -- must not be read or attributed to the in-root path
ln -s "$OUTSIDE/secret.php" "$ROOT/escapefile.php"

# 4. circular symlinks, self and mutual
ln -s loop.php "$ROOT/loop.php"
ln -s pong.php "$ROOT/ping.php"
ln -s ping.php "$ROOT/pong.php"

# 4b. dangling symlink
ln -s "$ROOT/does-not-exist.php" "$ROOT/dangling.php"

# 5. unreadable file -- silently dropped before the fix, while the run reported success
printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$ROOT/unreadable.php"
chmod 000 "$ROOT/unreadable.php"

# 5b. unreadable directory -- must cost only its own contents
mkdir -p "$ROOT/locked"
printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$ROOT/locked/inner.php"
chmod 000 "$ROOT/locked"

# 6. FIFO -- os.Open blocks forever, before any read bound can apply
mkfifo "$ROOT/pipe.php"

# 7. unix socket -- what php-fpm or gunicorn leaves in a webroot
python3 - "$ROOT/app.sock.php" <<'PY' 2>/dev/null || echo "note: skipped the unix socket (no python3)"
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
PY

# 8. device symlinks -- endless, endless-random, and empty
ln -s /dev/zero "$ROOT/zero.php"
ln -s /dev/urandom "$ROOT/rand.php"
ln -s /dev/null "$ROOT/null.php"

# 9. hard link -- an ordinary directory entry; must be scanned like any other
ln "$ROOT/shell.php" "$ROOT/hard.php"

# 10. filename with a backslash and a space -- legal on Linux, a separator on Windows, and the
#     shape that corrupts a path passed through a text channel such as the engine's scan list
printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$ROOT/we ird\\name.php"

# 11. content with no extension -- the engine scans by content, so it must still be enumerated
printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$ROOT/noext"

# 12. oversize file -- past the in-memory read bound; the engine still scans it, the Go passes
#     decline it, and the difference must be disclosed rather than silent
head -c 34000000 /dev/zero > "$ROOT/big.php" 2>/dev/null
printf '%s' '<?php $x = $_GET["x"]; system($x);' >> "$ROOT/big.php"

cat <<EOF

Fixture built: $ROOT
  scan root : $ROOT
  off-limits: $OUTSIDE   (nothing under here may be reported -- FR-018)

Expected of any build that passes US3:
  - the scan TERMINATES, and memory stays bounded
  - shell.php, shell.pl, shell.py and encoded.php are all still reported
  - nothing under $OUTSIDE is reported, under any path
  - the skipped counters are non-zero and disclosed, and coverage reads 'degraded', not 'failed'

Clean up with: chmod -R u+rwX "$DIR" && rm -rf "$DIR"
EOF
