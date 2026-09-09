#!/usr/bin/env bash
# check-fixture-fs.sh -- refuse to run filesystem-semantics fixtures on a filesystem that cannot
# express them (T002).
#
# WHY THIS EXISTS. US3's fixtures assert what the scanner does with a FIFO, a device node, a dangling
# symlink, and a path that differs only by case. On a Windows-mounted path -- v9fs or drvfs under WSL --
# mkfifo fails and `A.php` and `a.php` are the same file. The fixtures then pass by testing nothing:
# every hostile entry the scanner was supposed to refuse was never created, so the scanner refused
# nothing and the suite went green. A green suite that examined nothing is worse than a red one.
#
# Measured on the verification host:
#
#   /mnt/c/...   v9fs   case-INSENSITIVE  fifo=NO   <- fixtures here are vacuous
#   $HOME        ext4   case-sensitive    fifo=yes  <- fixtures here are real
#
# Usage:  check-fixture-fs.sh <dir>
# Exit:   0 usable · 1 unusable (with the reason) · 2 could not tell
set -u

DIR="${1:-}"
if [ -z "$DIR" ]; then
  echo "usage: $(basename "$0") <fixture-directory>" >&2
  exit 2
fi
if [ ! -d "$DIR" ]; then
  echo "check-fixture-fs: $DIR is not a directory" >&2
  exit 2
fi

FS=$(stat -f -c %T "$DIR" 2>/dev/null || echo unknown)
WORK=$(mktemp -d "$DIR/.fixture-fs-check-XXXXXX" 2>/dev/null) || {
  # Not writable is "could not tell", not "unusable": the caller may have handed us a read-only
  # mount by mistake, and reporting that as a fixture-semantics failure would send them the wrong way.
  echo "check-fixture-fs: cannot create a working directory in $DIR (fs=$FS)" >&2
  exit 2
}
cleanup() { rm -rf "$WORK" 2>/dev/null; }
trap cleanup EXIT

fail=0
note() { printf '  %-22s %s\n' "$1" "$2"; }

echo "check-fixture-fs: $DIR (fs=$FS)"

# --- case sensitivity ---------------------------------------------------------------------------
# A case-insensitive filesystem collapses the two halves of every case-confusion fixture into one
# file, so the test can neither create the situation nor observe the scanner's answer to it.
: > "$WORK/CaseProbe"
if [ -e "$WORK/caseprobe" ]; then
  note "case sensitivity" "INSENSITIVE -- case-confusion fixtures cannot exist here"
  fail=1
else
  note "case sensitivity" "sensitive"
fi

# --- FIFOs -------------------------------------------------------------------------------------
# The reader-hangs-forever bug (a release blocker for this port) is only reproducible against a real
# FIFO. Without one the regression test proves nothing at all.
if mkfifo "$WORK/fifo" 2>/dev/null; then
  note "FIFO" "supported"
else
  note "FIFO" "NOT SUPPORTED -- the reader-hang regression cannot be tested here"
  fail=1
fi

# --- symlinks, including dangling ----------------------------------------------------------------
# Containment (FR-018) is about links that point outside the scanned tree; a dangling one is the
# cheapest case to arrange and the one that crashes naive walkers.
if ln -s /definitely/not/here "$WORK/dangling" 2>/dev/null && [ -L "$WORK/dangling" ]; then
  note "dangling symlink" "supported"
else
  note "dangling symlink" "NOT SUPPORTED -- containment fixtures cannot be built here"
  fail=1
fi

# --- unreadable files ---------------------------------------------------------------------------
# chmod 000 must actually deny the owner, which needs real POSIX permission bits. Skipped for root,
# who bypasses them by design -- that is not a filesystem fact and must not be reported as one.
: > "$WORK/noperm"
chmod 000 "$WORK/noperm" 2>/dev/null
if [ "$(id -u)" = "0" ]; then
  note "unreadable file" "not testable as root (root bypasses permission bits)"
elif [ -r "$WORK/noperm" ]; then
  note "unreadable file" "PERMISSIONS IGNORED -- unreadable-file fixtures cannot exist here"
  fail=1
else
  note "unreadable file" "supported"
fi
chmod 644 "$WORK/noperm" 2>/dev/null

# --- the execute bit ----------------------------------------------------------------------------
# NTFS cannot carry it. A staged tree here would ship a 0644 engine binary, which takes down the
# whole scan -- and that has happened.
: > "$WORK/exe"
chmod 755 "$WORK/exe" 2>/dev/null
if [ -x "$WORK/exe" ]; then
  note "execute bit" "supported"
else
  note "execute bit" "NOT CARRIED -- a staged tree here would ship non-executable binaries"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  cat >&2 <<EOF

check-fixture-fs: $DIR (fs=$FS) CANNOT express the semantics these fixtures assert.
Fixtures placed here would pass without testing anything, which is the failure this check exists to
prevent. Use a native Linux filesystem -- under WSL, somewhere in \$HOME rather than /mnt/<drive>.
EOF
  exit 1
fi

echo "check-fixture-fs: OK -- $DIR can express every semantic the fixtures need"
exit 0
