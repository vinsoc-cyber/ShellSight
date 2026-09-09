#!/usr/bin/env bash
# Assemble a SHELLSIGHT_PREBUILT_DIR from the probe binaries ALREADY in bin/.
#
# WHEN TO USE THIS INSTEAD OF build-prebuilt.sh
# ---------------------------------------------
# build-prebuilt.sh REBUILDS the .NET and Java probes, which needs a dotnet SDK and a JDK and takes
# minutes. Most repackaging runs do not change a probe at all -- they change Go code, rules or docs,
# and only need bin/VERSION and the Go binaries restamped so the package-integrity gate goes green.
# For those, rebuilding the probes is pure risk: a probe rebuilt from identical source can still
# differ byte-for-byte (compiler and SDK drift), which needlessly churns PROBE-HASHES.sha256.
#
# This path was previously tribal knowledge -- "reuse the cached prebuilt dir when probes are
# unchanged" -- which is exactly how bin/ came to sit 404 commits stale once already. It is a script
# now so it is discoverable and reviewable.
#
#   export SHELLSIGHT_PREBUILT_DIR=/tmp/ss-prebuilt
#   scripts/prebuilt-from-bin.sh && scripts/package.sh
#
# DO NOT use this when a probe's source has changed. It would repackage the OLD probe under a NEW
# version stamp, producing exactly the "bundle is not the product of this source tree" lie the gate
# exists to catch -- while the gate itself reports green. When in doubt, run build-prebuilt.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin"
OUT="${SHELLSIGHT_PREBUILT_DIR:?SHELLSIGHT_PREBUILT_DIR is required (the directory to populate)}"

fail() { echo "[prebuilt-from-bin] $*" >&2; exit 1; }

[ -d "$BIN" ] || fail "no bin/ to copy from -- use build-prebuilt.sh for a first build"

# Sources in bin/ -> destinations in the layout package.sh requires.
# Note the x86 rename: bin/ flattens it to dotnetmem-x86.exe, the prebuilt layout nests it.
need=(
  "third_party/yara-x/yr.exe:yara-x/yr.exe"
  "dotnetmem.exe:dotnet/x64/dotnetmem.exe"
  "dotnetmem.exe.config:dotnet/x64/dotnetmem.exe.config"
  "dotnetmem-x86.exe:dotnet/x86/dotnetmem.exe"
  "dotnetmem-x86.exe.config:dotnet/x86/dotnetmem.exe.config"
  "javamem.jar:java/javamem.jar"
  "javamem-agent.jar:java/javamem-agent.jar"
)

for pair in "${need[@]}"; do
  [ -f "$BIN/${pair%%:*}" ] || fail "bin/${pair%%:*} is missing -- bin/ is not a complete bundle"
done
ls "$BIN"/*.dll >/dev/null 2>&1 || fail "bin/ has no .dll files -- the .NET probe's dependencies are missing"

echo "[prebuilt-from-bin] staging -> $OUT"
rm -rf "$OUT"
mkdir -p "$OUT/yara-x" "$OUT/dotnet/x64" "$OUT/dotnet/x86" "$OUT/java"
for pair in "${need[@]}"; do
  dst="$OUT/${pair##*:}"
  mkdir -p "$(dirname "$dst")"
  cp "$BIN/${pair%%:*}" "$dst"
done
cp "$BIN"/*.dll "$OUT/dotnet/x64/"

# package.sh requires every non-manifest file to appear in SHA256SUMS exactly once.
echo "[prebuilt-from-bin] writing SHA256SUMS"
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | while IFS= read -r -d '' f; do
        printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "${f#./}"
      done > SHA256SUMS )

echo "[prebuilt-from-bin] done -> $OUT ($(grep -c . "$OUT/SHA256SUMS") files). Next: scripts/package.sh"
