#!/usr/bin/env bash
# Assert that every ELF in a directory is statically linked (spec 002, T004 / contract A4.4).
#
#   scripts/linux/check-static.sh dist/linux-amd64
#   scripts/linux/check-static.sh dist/linux-arm64
#
# WHY THIS IS A RELEASE GATE, NOT A NICETY
# ----------------------------------------
# The Linux port ships ONE archive per architecture and claims it covers every distribution. That
# claim rests entirely on this property. A binary with a PT_INTERP program header needs a dynamic
# loader; one referencing GLIBC_2.x symbols is bound to a glibc version range and will refuse to
# start on anything older -- and on musl distributions, on nothing at all. Either would silently
# reintroduce the per-distribution build axis that research.md R1 concluded does not exist.
#
# It is separate from verify-archive.sh on purpose. That script is what an OPERATOR runs against a
# published tarball on the target host, so it must stay self-contained and assume nothing about the
# repository. This one is the BUILD-side gate: it runs over a staged tree before anything is
# published, and it can be pointed at dist/ without packaging first.
#
# Requires readelf (binutils). Absent readelf this exits 2 rather than 0 -- an unchecked property
# must not read as a passing one.
set -uo pipefail

DIR="${1:?usage: check-static.sh <directory>}"
[ -d "$DIR" ] || { echo "no such directory: $DIR" >&2; exit 2; }

command -v readelf >/dev/null 2>&1 || {
  echo "check-static: readelf not found -- run this on a Linux host (or install binutils)." >&2
  echo "              Refusing to report success on a property that was never checked." >&2
  exit 2
}

checked=0
failed=0

while IFS= read -r -d '' f; do
  # ELF magic, read directly: a directory full of rules and jars is mostly not ELF, and `file` is
  # not guaranteed present on a minimal host.
  [ "$(od -An -tx1 -N4 "$f" | tr -d ' \n')" = "7f454c46" ] || continue
  checked=$((checked + 1))
  rel="${f#"$DIR/"}"

  if readelf -l "$f" 2>/dev/null | grep -q INTERP; then
    echo "FAIL  $rel: has PT_INTERP (needs a dynamic loader)" >&2
    failed=$((failed + 1))
    continue
  fi
  if readelf -V "$f" 2>/dev/null | grep -q 'GLIBC_2\.'; then
    echo "FAIL  $rel: references versioned GLIBC_2.x symbols" >&2
    failed=$((failed + 1))
    continue
  fi
  printf 'OK    %s (%s)\n' "$rel" "$(readelf -h "$f" | sed -n 's/^  Machine: *//p')"
done < <(find "$DIR" -type f -print0)

if [ "$checked" -eq 0 ]; then
  echo "check-static: no ELF binaries found under $DIR -- nothing was verified." >&2
  exit 2
fi

printf '%d ELF binar%s checked, %d not static\n' "$checked" "$([ "$checked" -eq 1 ] && echo y || echo ies)" "$failed"
[ "$failed" -eq 0 ]
