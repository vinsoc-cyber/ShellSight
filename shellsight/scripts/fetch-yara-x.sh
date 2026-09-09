#!/usr/bin/env bash
# Fetch the pinned YARA-X engine binaries into third_party/yara-x/.
#
# WHY THIS EXISTS
# ---------------
# third_party/ is gitignored (see .gitignore), so the engine is NOT in a clone. Without it:
#   - the benchmark harness will not start, and
#   - a fresh worktree scans with a crippled rule set and reports plausible-looking wrong numbers.
# That has already cost this project real measurement time. This script makes the fetch a
# documented, hash-verified, idempotent command instead of tribal knowledge.
#
# WHY THE VERSION IS PINNED
# -------------------------
# The Windows and Linux releases MUST run the identical engine version, or a detection difference
# between platforms cannot be attributed to us rather than to the engine. Changing VERSION below is
# a deliberate act that invalidates the parity measurement and requires re-measuring the corpus.
# See specs/002-linux-port/contracts/parity-measurement.md P1.3.
#
#   usage: scripts/fetch-yara-x.sh [target ...]
#          scripts/fetch-yara-x.sh                 # every target
#          scripts/fetch-yara-x.sh linux-amd64     # just one
#
# Requires: curl, tar, sha256sum. No network access is needed if the files are already present and
# their digests match.
set -euo pipefail

VERSION="1.17.0"
BASE="https://github.com/VirusTotal/yara-x/releases/download/v${VERSION}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="$ROOT/third_party/yara-x"

# target | archive name | path inside third_party/yara-x | sha256 of the EXTRACTED binary
#
# Digests are of the extracted executable, not the archive, because that is what actually gets
# shipped and hashed into bin/PROBE-HASHES.sha256. The windows digest below is the one already
# recorded in that manifest, so a mismatch here means the bundle and this script disagree.
TARGETS="
windows-amd64|yara-x-v${VERSION}-x86_64-pc-windows-msvc.zip|yr.exe|943a1c9851e2942a9295794d2a1ea2ac127695caebd3199d29925d6910e3dd91
linux-amd64|yara-x-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz|linux-amd64/yr|9c3f0c3ace53392f1875ea3d58c3fe97a79b78e3f91f445c346fa1e141ae71fb
linux-arm64|yara-x-v${VERSION}-aarch64-unknown-linux-gnu.tar.gz|linux-arm64/yr|fc27ccb67520ae203bd023b1c2508511fdd726f2ef5922352e7c3ab059509f4d
"

fail() { echo "[yara-x] $*" >&2; exit 1; }

command -v curl     >/dev/null || fail "curl not on PATH"
command -v sha256sum>/dev/null || fail "sha256sum not on PATH"

want=("$@")
matches_request() {
  [ ${#want[@]} -eq 0 ] && return 0
  local t="$1" w
  for w in "${want[@]}"; do [ "$w" = "$t" ] && return 0; done
  return 1
}

digest_of() { sha256sum "$1" | cut -d' ' -f1; }

fetched=0 skipped=0
while IFS='|' read -r target archive relpath want_sha; do
  [ -z "${target:-}" ] && continue
  matches_request "$target" || continue

  out="$DEST/$relpath"
  if [ -f "$out" ] && [ "$(digest_of "$out")" = "$want_sha" ]; then
    echo "[yara-x] $target already present and verified"
    skipped=$((skipped + 1))
    continue
  fi
  [ -f "$out" ] && echo "[yara-x] $target present but digest MISMATCHED — refetching"

  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  echo "[yara-x] fetching $target ($archive)"
  curl -fsSL --retry 3 --max-time 600 -o "$tmp/$archive" "$BASE/$archive" \
    || fail "download failed for $target — if DNS is broken inside WSL, run this on the host and copy third_party/ across"

  case "$archive" in
    *.tar.gz) tar -xzf "$tmp/$archive" -C "$tmp" ;;
    *.zip)    command -v unzip >/dev/null && unzip -qo "$tmp/$archive" -d "$tmp" \
                || 7z x -y -o"$tmp" "$tmp/$archive" >/dev/null \
                || fail "need unzip or 7z to unpack $archive" ;;
    *)        fail "unknown archive type: $archive" ;;
  esac

  # The archives contain a single executable, but do not assume its location.
  base="${relpath##*/}"
  src="$(find "$tmp" -type f -name "$base" ! -name '*.zip' ! -name '*.tar.gz' | head -1)"
  [ -n "$src" ] || fail "$base not found inside $archive"

  mkdir -p "$(dirname "$out")"
  cp "$src" "$out"
  chmod +x "$out"

  got="$(digest_of "$out")"
  [ "$got" = "$want_sha" ] || fail "digest mismatch for $target
  expected $want_sha
  got      $got
This means the upstream asset changed under a fixed tag. Do NOT update the digest without
establishing why, and re-measure the corpus if the engine really did change."

  echo "[yara-x] $target -> ${out#"$ROOT"/}  (verified)"
  fetched=$((fetched + 1))
done <<< "$TARGETS"

echo "[yara-x] done: $fetched fetched, $skipped already verified (engine pinned at v${VERSION})"
