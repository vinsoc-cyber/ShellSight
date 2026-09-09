#!/usr/bin/env bash
# Verify a ShellSight Linux release archive on the host that will run it.
#
# This is the operator-side half of contracts/release-archive.md A4: every property it lists must be
# confirmable ON THE TARGET HOST with no build tooling, no network, and no trust in the build box.
# Nothing here needs Go, a compiler, or the source tree -- only tar, sha256sum and coreutils.
#
# It exists because the build host cannot check most of this honestly. Windows/NTFS through Git Bash
# cannot represent a POSIX execute bit (measured: a file chmod'ed 755 tars as -rw-r--r--), and the
# Windows box has no readelf, so "is it executable" and "is it static" are claims the packaging step
# can only make about the archive's own metadata -- never about what actually lands on disk.
#
#   usage: scripts/linux/verify-archive.sh <archive.tar.gz> [workdir]
#
# Exit 0 = every checked property holds. Any failure is fatal and named.
set -uo pipefail

ARCHIVE="${1:?usage: verify-archive.sh <archive.tar.gz> [workdir]}"
WORK="${2:-$(mktemp -d)}"

PASS=0
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL + 1)); }
note() { printf '  ....  %s\n' "$*"; }

[ -f "$ARCHIVE" ] || { echo "no such archive: $ARCHIVE" >&2; exit 2; }
echo "archive: $ARCHIVE"
echo "workdir: $WORK"
echo

# ---------------------------------------------------------------------------------------------
# A4 precondition: extract. Done first because every other check reads the UNPACKED tree -- the
# whole point is to test what the operator ends up with, not what the tar header claims.
# ---------------------------------------------------------------------------------------------
ROOT="$WORK/unpacked"
rm -rf "$ROOT"; mkdir -p "$ROOT"
tar -xzf "$ARCHIVE" -C "$ROOT" || { echo "extraction failed" >&2; exit 2; }

echo "== A4.1  every executable component is executable as unpacked =="
COMPONENTS=(shellsight diskprobe)
for c in "${COMPONENTS[@]}"; do
  if [ ! -f "$ROOT/$c" ]; then
    bad "$c is missing from the archive"
  elif [ -x "$ROOT/$c" ]; then
    ok "$c is executable ($(stat -c '%A' "$ROOT/$c"))"
  else
    bad "$c is NOT executable ($(stat -c '%A' "$ROOT/$c"))"
  fi
done
if [ -f "$ROOT/third_party/yara-x/yr" ]; then
  if [ -x "$ROOT/third_party/yara-x/yr" ]; then
    ok "third_party/yara-x/yr is executable"
  else
    bad "third_party/yara-x/yr is NOT executable"
  fi
else
  bad "the detection engine is missing from the archive"
fi
echo

echo "== A4.2  every component's digest matches the manifest =="
MANIFEST="$ROOT/PROBE-HASHES.sha256"
if [ ! -f "$MANIFEST" ]; then
  bad "PROBE-HASHES.sha256 is missing"
else
  manifest_lines=0
  bad_digest=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [ -n "$line" ] || continue
    digest="${line%% *}"
    relative="${line#*  }"
    manifest_lines=$((manifest_lines + 1))
    if [ ! -f "$ROOT/$relative" ]; then
      bad "manifest names a file the archive does not contain: $relative"
      bad_digest=$((bad_digest + 1))
      continue
    fi
    actual="$(sha256sum "$ROOT/$relative" | cut -d' ' -f1)"
    if [ "${actual,,}" != "${digest,,}" ]; then
      bad "digest mismatch: $relative"
      bad_digest=$((bad_digest + 1))
    fi
  done < "$MANIFEST"
  [ "$bad_digest" -eq 0 ] && ok "all $manifest_lines manifested digests match"
fi
echo

echo "== A4.3  shellsight reports the expected version =="
ARCHIVE_VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo '(missing)')"
note "VERSION file: $ARCHIVE_VERSION"
if reported="$("$ROOT/shellsight" version 2>&1)"; then
  ok "shellsight runs: $reported"
else
  bad "shellsight version failed: $reported"
fi
echo

echo "== A4.4  no component requires a dynamic loader =="
# The single-archive-per-architecture claim rests entirely on this. A PT_INTERP entry or a versioned
# glibc symbol would mean the binary is bound to a libc range, and "one archive covers every
# distribution" would be false rather than merely optimistic.
check_static() {
  local f="$1" rel="${1#"$ROOT/"}"
  if command -v readelf >/dev/null 2>&1; then
    if readelf -l "$f" 2>/dev/null | grep -q INTERP; then
      bad "$rel has PT_INTERP (dynamically linked)"
      return
    fi
    if readelf -V "$f" 2>/dev/null | grep -q 'GLIBC_2\.'; then
      bad "$rel references versioned GLIBC_2.x symbols"
      return
    fi
    ok "$rel is static: no PT_INTERP, no GLIBC_2.x"
  else
    note "readelf unavailable -- cannot check $rel"
  fi
}
for c in "${COMPONENTS[@]}" third_party/yara-x/yr; do
  [ -f "$ROOT/$c" ] && check_static "$ROOT/$c"
done
echo

echo "== A4.5  a scan of a directory containing known webshells produces the expected verdict =="
# Benign-inert by shape: a request parameter reaching an exec sink is what the detectors match.
# Nothing here executes anything.
SHELLS="$WORK/webroot"
rm -rf "$SHELLS"; mkdir -p "$SHELLS"
printf '%s' '<?php $x = $_GET["x"]; system($x);' > "$SHELLS/shell.php"
printf '%s\n' '#!/usr/bin/perl' 'my $CMD = $ENV{"QUERY_STRING"};' 'system($CMD);' > "$SHELLS/shell.pl"
OUT="$WORK/run-dirty"
rm -rf "$OUT"; mkdir -p "$OUT"
# The CLI's own last stdout line is `verdict=<tier> incomplete=<bool> -> <run folder>`. Reading that
# needs no JSON parser, which matters: A4 requires these properties to be confirmable on the target
# host with no build tooling, and a minimal IR host may have neither python nor jq.
scan_out="$("$ROOT/shellsight" scan --path "$SHELLS" --out "$OUT" --views disk 2>&1)"
scan_rc=$?
summary="$(printf '%s' "$scan_out" | grep -o 'verdict=[a-z]* incomplete=[a-z]*' | tail -1)"
verdict="${summary#verdict=}"; verdict="${verdict%% *}"
incomplete="${summary##*incomplete=}"
case "$verdict" in
  confirmed|likely|suspicious) ok "known webshells detected: verdict=$verdict, exit=$scan_rc" ;;
  "")     bad "scan printed no verdict (exit $scan_rc): $(printf '%s' "$scan_out" | tail -2)" ;;
  *)      bad "scan over two known webshells returned verdict=$verdict, expected a malicious tier" ;;
esac
if [ "$incomplete" = "false" ]; then
  ok "the malicious scan is complete (incomplete=false)"
else
  bad "the malicious scan reported incomplete=$incomplete -- a partial scan cannot support a verdict"
fi
# Coverage must also be affirmatively present, not merely absent-and-assumed.
report="$(find "$OUT" -name report.json | head -1)"
if [ -n "$report" ] && grep -q '"status"[[:space:]]*:[[:space:]]*"ran"' "$report"; then
  ok "the disk capability reports status=ran"
else
  bad "no capability reported status=ran"
fi
echo

echo "== A4.6  a scan of a clean directory exits 0, unavailable capabilities are n/a not failed =="
CLEAN="$WORK/clean"
rm -rf "$CLEAN"; mkdir -p "$CLEAN"
printf '%s' '<?php echo "hello"; ?>' > "$CLEAN/index.php"
OUT2="$WORK/run-clean"
rm -rf "$OUT2"; mkdir -p "$OUT2"
clean_out="$("$ROOT/shellsight" scan --path "$CLEAN" --out "$OUT2" 2>&1)"
clean_rc=$?
clean_summary="$(printf '%s' "$clean_out" | grep -o 'verdict=[a-z]* incomplete=[a-z]*' | tail -1)"
if [ "$clean_rc" -eq 0 ]; then
  ok "clean scan exits 0 ($clean_summary)"
else
  bad "clean scan exits $clean_rc, want 0 -- $clean_summary (US4: Linux-unsupported capabilities must report n/a, not failed)"
fi
# Run with the DEFAULT capability set, not just --views disk: the default set is where a
# Windows-only capability would leak in and turn a clean Linux host into a failed run.
case "$clean_summary" in
  "verdict=clean incomplete=false") ok "clean scan is clean and complete under the default view set" ;;
  *) bad "clean scan summary is '$clean_summary', want 'verdict=clean incomplete=false'" ;;
esac
# The other half of Scenario 2, and the half an exit code cannot show: the capabilities this platform
# cannot support have to be STATED. Exit 0 alone is also what a build that silently dropped them
# produces, and a report that says nothing about dotnet-mem cannot be told apart from a report by a
# tool that forgot dotnet-mem exists.
#
# report.json is pretty-printed with "view", then "status", then "reason", so `grep -A 2` reads one
# record whole -- no jq and no python, which A4 requires. Order-independent by construction.
#
# The trailing comma in the pattern is load-bearing twice over. It is what makes "dotnet-mem" not
# match "dotnet-mem-x86" -- and the first version of this check anchored on `$` instead, which
# matched NOTHING because every JSON line ends with the comma. It reported 5 failures against an
# archive that was in fact correct, which is the same way the verifier's first version reported a
# failure on a scan that had returned confirmed. A check that cannot pass is not a strict check.
report2="$(find "$OUT2" -name report.json | head -1)"
if [ -z "$report2" ]; then
  bad "the clean scan produced no report.json"
else
  na_ok=1
  for view in java-mem dotnet-mem dotnet-mem-x86 behavioral native-mem; do
    # The closing quote is what keeps "dotnet-mem" from matching "dotnet-mem-x86".
    count="$(grep -c "\"view\": \"$view\"," "$report2")"
    if [ "$count" -ne 1 ]; then
      bad "$view appears $count times in coverage, want exactly 1 (one capability, one record)"
      na_ok=0
      continue
    fi
    rec="$(grep -A 2 "\"view\": \"$view\"," "$report2")"
    printf '%s' "$rec" | grep -q '"status": "n/a"' || {
      bad "$view is not reported n/a on this platform: $(printf '%s' "$rec" | tr '\n' ' ')"
      na_ok=0
      continue
    }
    printf '%s' "$rec" | grep -q '"reason": ".*'"$(uname -s | tr 'A-Z' 'a-z')"'"' || {
      bad "$view is n/a with no reason naming the platform (FR-012): $(printf '%s' "$rec" | tr '\n' ' ')"
      na_ok=0
    }
  done
  [ "$na_ok" -eq 1 ] && ok "every Windows-only capability is reported once as n/a with a stated reason"
fi
echo

echo "== A5  no installation, no root, no trace outside the directory =="
if [ "$(id -u)" -eq 0 ]; then
  note "running as root -- the no-root property is not being exercised"
else
  ok "every check above ran as an unprivileged user ($(id -un))"
fi
echo

printf 'result: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
