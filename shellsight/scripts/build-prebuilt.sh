#!/usr/bin/env bash
# Build the SHELLSIGHT_PREBUILT_DIR that scripts/package.sh consumes.
#
# package.sh deliberately refuses to build the .NET and Java probes itself — it stages only
# hash-verified inputs. But nothing documented how to PRODUCE those inputs, so re-packaging became
# an undocumented ritual and simply stopped happening: on 2026-08-10 the bundle in bin/ was found to
# be 404 commits stale (built 2026-06-17 from a dirty tree), missing every PHP taint fix, the chr()
# fold, the AntSword rule and the rule-identity fix, while its rules had been hand-refreshed on top.
# That is what this script exists to prevent. Release is now two commands:
#
#   export SHELLSIGHT_PREBUILT_DIR=/tmp/ss-prebuilt
#   scripts/build-prebuilt.sh && scripts/package.sh
#
#   scripts/build-prebuilt.sh linux-amd64          # then: GOOS=linux GOARCH=amd64 scripts/package.sh
#   scripts/build-prebuilt.sh linux-arm64          # then: GOOS=linux GOARCH=arm64 scripts/package.sh
#
# TARGETS
# -------
# windows-amd64 (default) needs a dotnet SDK (net462 reference assemblies), a JDK (javac/jar), and a
# yr.exe to carry over. A LINUX prebuilt directory needs NONE of those: the only non-Go component
# that ships on Linux is the engine, because the .NET, native-memory and behavioural probes are
# Windows-only by contract and java-mem is deferred to US5. So the Linux path deliberately does not
# require -- or invoke -- either toolchain; demanding a dotnet SDK to package a Linux archive that
# contains no .NET would be a build dependency with nothing behind it.
#
# The engine binaries come from third_party/yara-x/, which scripts/fetch-yara-x.sh populates with
# hash-verified downloads pinned to one version across every platform. That pinning is what makes a
# cross-platform detection difference attributable to us rather than to the engine.
#
# Verify the result with `go test ./internal/bundle/ -run TestRepoBundleIsShippable`.
set -euo pipefail

TARGET="${1:-windows-amd64}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
OUT="${SHELLSIGHT_PREBUILT_DIR:?SHELLSIGHT_PREBUILT_DIR is required (the directory to populate)}"
DOTNET_PROJ="$ROOT/probes/dotnetmem/src/Dotnetmem.csproj"
X64_OUT="$ROOT/probes/dotnetmem/src/bin/Release/net462"
X86_OUT="$ROOT/probes/dotnetmem/src/bin-x86/Release/net462"

fail() { echo "[prebuilt] $*" >&2; exit 1; }

# write_manifest is shared by every target: package.sh requires every non-manifest file to appear in
# SHA256SUMS exactly once.
write_manifest() {
  echo "[prebuilt] writing SHA256SUMS"
  ( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 \
      | sort -z \
      | while IFS= read -r -d '' f; do
          rel="${f#./}"
          printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$rel"
        done > SHA256SUMS )
  local count
  count="$(grep -c . "$OUT/SHA256SUMS")"
  echo "[prebuilt] done -> $OUT ($count files). Next: scripts/package.sh"
}

case "$TARGET" in
  linux-amd64|linux-arm64)
    arch="${TARGET#linux-}"
    YR="${SHELLSIGHT_YR_LINUX:-$REPO_ROOT/third_party/yara-x/$TARGET/yr}"
    [ -f "$YR" ] || fail "linux engine not found at $YR -- run scripts/fetch-yara-x.sh $TARGET"

    # The engine must be an ELF of the RIGHT architecture, checked before it is staged rather than
    # discovered on the target host. Read straight out of the ELF header with od, NOT with readelf:
    # the Windows build host has no binutils, and a check that silently skips itself on the one host
    # where the cross-architecture mistake is actually possible is not a check.
    #
    # e_ident[0..3] = 7f 45 4c 46 ("\x7fELF"); e_machine is the 16-bit LE field at offset 18.
    # 0x003e = x86-64, 0x00b7 = AArch64.
    elf_magic="$(od -An -tx1 -N4 "$YR" | tr -d ' \n')"
    [ "$elf_magic" = "7f454c46" ] || fail "engine at $YR is not an ELF binary (magic $elf_magic)"
    e_machine="$(od -An -tx2 -j18 -N2 --endian=little "$YR" 2>/dev/null | tr -d ' \n')"
    case "$arch:$e_machine" in
      amd64:003e|arm64:00b7) ;;
      *) fail "engine at $YR has e_machine=0x$e_machine, which is not $arch" ;;
    esac

    # Static linkage keeps ONE archive per architecture covering every distribution (contract A4.4).
    # PT_INTERP needs a program-header walk, so this arm does need readelf; when it is unavailable
    # the property is asserted later by scripts/linux/check-static.sh on a Linux host, and saying so
    # is better than implying it was checked here.
    if command -v readelf >/dev/null 2>&1; then
      readelf -l "$YR" 2>/dev/null | grep -q INTERP \
        && fail "engine at $YR is dynamically linked (has PT_INTERP); the archive would not be distro-portable"
    else
      echo "[prebuilt] note: readelf unavailable -- PT_INTERP unchecked here; run scripts/linux/check-static.sh on a Linux host" >&2
    fi

    echo "[prebuilt] staging -> $OUT ($TARGET, engine only)"
    rm -rf "$OUT"
    mkdir -p "$OUT/yara-x"
    cp "$YR" "$OUT/yara-x/yr"
    write_manifest
    exit 0
    ;;
  windows-amd64)
    ;;
  *)
    fail "unsupported target: $TARGET (windows-amd64, linux-amd64, linux-arm64)"
    ;;
esac

# yr.exe is a third-party binary we carry rather than build. Prefer an explicit path.
YR="${SHELLSIGHT_YR_EXE:-$ROOT/bin/third_party/yara-x/yr.exe}"

command -v dotnet >/dev/null || fail "dotnet SDK not on PATH"
command -v javac  >/dev/null || fail "javac not on PATH (a JDK is required)"
[ -f "$YR" ] || fail "yr.exe not found at $YR (set SHELLSIGHT_YR_EXE)"

echo "[prebuilt] building dotnetmem x64 (AnyCPU)"
# AnyCPU without 32BITPREFERRED runs 64-bit on 64-bit Windows, which is what the x64 slot needs.
# Note: .NET Framework assemblies keep PE machine 0x014c whatever the target, so bitness is NOT
# readable from the PE header — check CorFlags (ILONLY vs ILONLY|32BITREQUIRED) instead.
dotnet build "$DOTNET_PROJ" -c Release >/dev/null || fail "x64 build failed"

echo "[prebuilt] building dotnetmem x86 (32BITREQUIRED, for 32-bit app pools)"
dotnet build "$DOTNET_PROJ" -c Release -p:PlatformTarget=x86 -p:BaseOutputPath=bin-x86/ >/dev/null \
  || fail "x86 build failed"

echo "[prebuilt] building javamem jars"
# probes/javamem/build.sh copies its output straight into bin/ as a side effect. Populating the
# prebuilt dir must not mutate an already-packaged bundle, so snapshot those two files and put them
# back — otherwise bin/ ends up with jars that no longer match its own PROBE-HASHES.sha256 while
# VERSION and the rules still look correct, which is exactly the drift this whole path exists to
# prevent. (`go test ./internal/bundle/` now detects that case if it ever slips through.)
JAR_BACKUP="$(mktemp -d)"
trap 'rm -rf "$JAR_BACKUP"' EXIT
for j in javamem.jar javamem-agent.jar; do
  [ -f "$ROOT/bin/$j" ] && cp "$ROOT/bin/$j" "$JAR_BACKUP/$j"
done
bash "$ROOT/probes/javamem/build.sh" >/dev/null || fail "javamem build failed"
for j in javamem.jar javamem-agent.jar; do
  [ -f "$JAR_BACKUP/$j" ] && cp "$JAR_BACKUP/$j" "$ROOT/bin/$j"
done

for f in "$X64_OUT/dotnetmem.exe" "$X64_OUT/dotnetmem.exe.config" \
         "$X86_OUT/dotnetmem.exe" "$X86_OUT/dotnetmem.exe.config" \
         "$ROOT/probes/javamem/javamem.jar" "$ROOT/probes/javamem/javamem-agent.jar"; do
  [ -f "$f" ] || fail "expected build output missing: $f"
done

echo "[prebuilt] staging -> $OUT"
rm -rf "$OUT"
mkdir -p "$OUT/yara-x" "$OUT/dotnet/x64" "$OUT/dotnet/x86" "$OUT/java"
cp "$YR"                                   "$OUT/yara-x/yr.exe"
cp "$X64_OUT/dotnetmem.exe"                "$OUT/dotnet/x64/dotnetmem.exe"
cp "$X64_OUT/dotnetmem.exe.config"         "$OUT/dotnet/x64/dotnetmem.exe.config"
cp "$X64_OUT"/*.dll                        "$OUT/dotnet/x64/"
cp "$X86_OUT/dotnetmem.exe"                "$OUT/dotnet/x86/dotnetmem.exe"
cp "$X86_OUT/dotnetmem.exe.config"         "$OUT/dotnet/x86/dotnetmem.exe.config"
cp "$ROOT/probes/javamem/javamem.jar"      "$OUT/java/javamem.jar"
cp "$ROOT/probes/javamem/javamem-agent.jar" "$OUT/java/javamem-agent.jar"

write_manifest
