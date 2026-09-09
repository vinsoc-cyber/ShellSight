#!/usr/bin/env bash
# Assemble a complete release from a fresh, literal allowlisted stage.
#
#   scripts/package.sh                          # windows/amd64 (the default, unchanged)
#   GOOS=linux GOARCH=amd64 scripts/package.sh
#   GOOS=linux GOARCH=arm64 scripts/package.sh
#
# ONE SCRIPT, NOT TWO
# -------------------
# Everything below the target descriptor -- manifest validation, the forbidden-name allowlist, the
# staged-digest mapping, the extract-and-re-verify pass -- is platform-independent and is shared
# verbatim. A separate package-linux.sh would have had to copy all of it, and a copied integrity
# check is one that can quietly stop matching the original while both still look right. So the
# platform differences are declared as DATA in configure_target and the machinery iterates it.
#
# Required prebuilt layout (windows):
#   SHELLSIGHT_PREBUILT_DIR/
#     SHA256SUMS
#     yara-x/yr.exe
#     dotnet/x64/dotnetmem.exe
#     dotnet/x64/dotnetmem.exe.config
#     dotnet/x64/*.dll                  (one or more runtime dependencies)
#     dotnet/x86/dotnetmem.exe
#     dotnet/x86/dotnetmem.exe.config
#     java/javamem.jar
#     java/javamem-agent.jar
#
# Required prebuilt layout (linux):
#   SHELLSIGHT_PREBUILT_DIR/
#     SHA256SUMS
#     yara-x/yr
#
# SHA256SUMS contains lowercase or uppercase SHA-256 plus two spaces and a
# forward-slash relative path. Every non-manifest file must appear exactly once.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO="${GO:-/c/Program Files/Go/bin/go.exe}"
PREBUILT="${SHELLSIGHT_PREBUILT_DIR:?SHELLSIGHT_PREBUILT_DIR is required; see Required prebuilt layout in scripts/package.sh}"

TARGET_GOOS="${GOOS:-windows}"
TARGET_GOARCH="${GOARCH:-amd64}"
TARGET="$TARGET_GOOS-$TARGET_GOARCH"

# Per-target declarations. Populated by configure_target; read by the shared machinery below.
declare -a GO_COMPONENTS=()        # "<staged name>:<go package>"
declare -a REQUIRED_PREBUILT=()    # paths that MUST appear in SHA256SUMS
declare -a PREBUILT_STAGING=()     # "<prebuilt relative>:<staged relative>"
declare -a REQUIRED_ARCHIVE=()     # paths that MUST exist after extraction
declare -a APPROVED_PREBUILT=()    # paths SHA256SUMS is allowed to name
declare -a APPROVED_STAGED=()      # staged paths PROBE-HASHES.sha256 is allowed to name
declare -a EXECUTABLE_STAGED=()    # staged paths that MUST unpack executable (tar targets only)
REQUIRE_DOTNET_DLLS=0
ARCHIVE_KIND=""
ARCHIVE_SUFFIX=""

configure_target() {
  case "$TARGET_GOOS" in
    windows)
      # The historical layout, unchanged. bin/ IS the Windows install, so a Windows package run
      # still replaces it in place and still preserves operator state across the swap.
      ARCHIVE_KIND="zip"
      ARCHIVE_SUFFIX="win.zip"
      FINAL_BIN="$ROOT/bin"
      REQUIRE_DOTNET_DLLS=1
      GO_COMPONENTS=(
        "shellsight.exe:./cmd/shellsight"
        "diskprobe.exe:./cmd/diskprobe"
        "behaviorprobe.exe:./cmd/behaviorprobe"
        "nativemem.exe:./cmd/nativemem"
      )
      APPROVED_PREBUILT=(
        yara-x/yr.exe
        dotnet/x64/dotnetmem.exe dotnet/x64/dotnetmem.exe.config
        dotnet/x86/dotnetmem.exe dotnet/x86/dotnetmem.exe.config
        java/javamem.jar java/javamem-agent.jar
      )
      REQUIRED_PREBUILT=("${APPROVED_PREBUILT[@]}")
      PREBUILT_STAGING=(
        "yara-x/yr.exe:third_party/yara-x/yr.exe"
        "dotnet/x64/dotnetmem.exe:dotnetmem.exe"
        "dotnet/x64/dotnetmem.exe.config:dotnetmem.exe.config"
        "dotnet/x86/dotnetmem.exe:dotnetmem-x86.exe"
        "dotnet/x86/dotnetmem.exe.config:dotnetmem-x86.exe.config"
        "java/javamem.jar:javamem.jar"
        "java/javamem-agent.jar:javamem-agent.jar"
      )
      APPROVED_STAGED=(
        third_party/yara-x/yr.exe
        dotnetmem.exe dotnetmem.exe.config dotnetmem-x86.exe dotnetmem-x86.exe.config
        javamem.jar javamem-agent.jar
      )
      REQUIRED_ARCHIVE=(
        shellsight.exe diskprobe.exe behaviorprobe.exe nativemem.exe
        kb/rules/mem-contracts.json VERSION RUNBOOK.md PROBE-HASHES.sha256 RELEASE-FILES.sha256
        components.json
        third_party/yara-x/yr.exe
        dotnetmem.exe dotnetmem.exe.config dotnetmem-x86.exe dotnetmem-x86.exe.config
        javamem.jar javamem-agent.jar
      )
      ;;
    linux)
      # A Linux run must NEVER touch bin/ -- that is this box's Windows install. Overwriting it with
      # Linux ELFs would leave the freshness gate green while the bundle was unrunnable, which is
      # precisely the "invalid evidence" failure release-archive.md A6 exists to prevent.
      ARCHIVE_KIND="tar.gz"
      ARCHIVE_SUFFIX="linux-$TARGET_GOARCH.tar.gz"
      FINAL_BIN="$ROOT/dist/$TARGET"
      REQUIRE_DOTNET_DLLS=0
      GO_COMPONENTS=(
        "shellsight:./cmd/shellsight"
        "diskprobe:./cmd/diskprobe"
        "jvmprobe:./cmd/jvmprobe"
      )
      # behaviorprobe, nativemem and dotnetmem are ABSENT by contract (release-archive.md A2): each
      # reads a Windows-only facility, so shipping the binary would advertise a capability that
      # cannot run.
      #
      # java-mem SHIPS here, as the native cmd/jvmprobe. It speaks the HotSpot attach protocol
      # directly and carries the agent jar EMBEDDED via go:embed, so no JRE is needed on the target
      # and no loose jar is packaged. Shipping javamem.jar alongside would create a second agent
      # that can drift from the embedded one, so it is deliberately absent.
      #
      # The live validation the old deferral asked for is
      # docs/measurements/2026-08-31-tomcat-memshell-corpus: 92 real resident fileless memshells,
      # 8 tools, 17 component types, recall 84/92 at zero false positives on clean Tomcat 9 and 10.
      APPROVED_PREBUILT=(yara-x/yr)
      REQUIRED_PREBUILT=("${APPROVED_PREBUILT[@]}")
      PREBUILT_STAGING=("yara-x/yr:third_party/yara-x/yr")
      APPROVED_STAGED=(third_party/yara-x/yr)
      REQUIRED_ARCHIVE=(
        shellsight diskprobe jvmprobe
        kb/rules/mem-contracts.json VERSION RUNBOOK.md PROBE-HASHES.sha256 RELEASE-FILES.sha256
        components.json
        third_party/yara-x/yr
      )
      # The ENGINE belongs here too, not just the Go components. Leaving it out shipped it 0644 and
      # cost the entire scan: diskprobe could not exec it, the disk view reported failed, and a run
      # over two known webshells returned verdict=unknown with zero findings. A zip records its own
      # modes so this list is only consulted for tar targets.
      EXECUTABLE_STAGED=(shellsight diskprobe jvmprobe third_party/yara-x/yr)
      ;;
    *)
      echo "[package] unsupported GOOS: $TARGET_GOOS (windows, linux)" >&2
      exit 1
      ;;
  esac

  case "$TARGET_GOARCH" in
    amd64|arm64) ;;
    *) echo "[package] unsupported GOARCH: $TARGET_GOARCH (amd64, arm64)" >&2; exit 1 ;;
  esac
  if [ "$TARGET_GOOS" = "windows" ] && [ "$TARGET_GOARCH" != "amd64" ]; then
    echo "[package] only windows-amd64 is supported for GOOS=windows" >&2
    exit 1
  fi
}
configure_target

# in_list reports whether $1 appears verbatim in the remaining arguments.
in_list() {
  local needle="$1"; shift
  local item
  for item in "$@"; do
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}
PREBUILT_MANIFEST="$PREBUILT/SHA256SUMS"
STAGE_ROOT="$(mktemp -d "$ROOT/.package-stage.XXXXXX")"
BIN="$STAGE_ROOT/bin"
OLD_BIN="$STAGE_ROOT/previous-bin"
VERIFY_DIR="$STAGE_ROOT/archive-verify"
HASH_FILE="$BIN/PROBE-HASHES.sha256"
# The release's complete inventory, for a consumer that ingests a release it did not build.
# Distinct from PROBE-HASHES.sha256 by design -- see write_release_manifest.
RELEASE_MANIFEST_NAME="RELEASE-FILES.sha256"

declare -A PREBUILT_HASHES=()
declare -A PREBUILT_PATHS=()
declare -A STAGED_EXPECTED_HASHES=()
declare -A STAGED_DESTINATIONS=()
declare -A STAGED_SOURCES=()
declare -a DOTNET_DLL_PATHS=()

cleanup() {
  rm -rf "$STAGE_ROOT"
}
trap cleanup EXIT

fail() {
  echo "[package] $*" >&2
  exit 1
}

sha256_file() {
  local file="$1"
  local output
  # Fed on STDIN rather than as an argument. GNU coreutils escapes a filename that contains a
  # backslash -- it doubles the separators and marks the line with a leading "\" -- so
  #
  #   sha256sum "C:\prebuilt\yr.exe"  ->  \<digest> *C:\\prebuilt\\yr.exe
  #
  # and the field picked out of that is 65 characters beginning with a backslash. Measured
  # 2026-09-04: with a Windows-style SHELLSIGHT_PREBUILT_DIR every comparison in this script failed
  # as "prebuilt hash mismatch", which reads as tampering and is not -- and the release-packaging
  # fixture in cmd/corpusctl, which passes exactly such a path, had never once reached the tamper
  # guards it exists to exercise. On stdin there is no filename for coreutils to escape.
  output="$(sha256sum < "$file")" || return 1
  printf '%s\n' "${output%% *}"
}

is_forbidden_release_path() {
  local relative="${1,,}"
  local base="${relative##*/}"
  case "$base" in
    corpusctl|corpusctl.*|measure|measure.*|mockprobe|mockprobe.*|victim_clean|victim_clean.*|victim_implant|victim_implant.*|victim_stomp|victim_stomp.*|nativemem_lab|nativemem_lab.*|nativemem-lab|nativemem-lab.*)
      return 0
      ;;
  esac
  case "/$relative/" in
    *"/cmd/nativemem/lab/"*) return 0 ;;
  esac
  return 1
}

validate_relative_path() {
  local relative="$1"
  case "$relative" in
    /*|\\*|[A-Za-z]:*) fail "absolute prebuilt path: $relative" ;;
    *\\*) fail "unapproved prebuilt path separator: $relative" ;;
  esac
  case "/$relative/" in
    *"/../"*|*"/./"*|*"//"*) fail "prebuilt path traversal: $relative" ;;
  esac
  if is_forbidden_release_path "$relative"; then
    fail "forbidden tool or lab name in prebuilt path: $relative"
  fi
}

# write_release_manifest records EVERY staged file in RELEASE-FILES.sha256.
#
# This is NOT PROBE-HASHES.sha256 and must never be folded into it. That file is the prebuilt-asset
# attribution record: `verify_extracted_prebuilt_hashes` refuses any entry that is not an approved
# prebuilt path, and internal/bundle re-hashes its entries RAW, so naming a text file there would
# break under core.autocrlf. This one is the opposite -- the release's complete inventory, which is
# what an ingesting consumer needs to verify a release it did not build.
#
# It exists because console/internal/release.Verify is two-directional: a file on disk the manifest
# does not name is a verification failure, so it could never ingest a release whose only manifest
# was the partial probe list. Measured 2026-09-08 on shellsight-v1.0.1-20-g687b745-win.zip:
# PROBE-HASHES named 144 of 164 files, omitting shellsight.exe, diskprobe.exe, components.json,
# VERSION, RUNBOOK.md and all of kb/**, so `console publish` refused every release this script has
# ever produced -- and with it every agent build, because generation reads the published files.
#
# The manifest cannot name itself: its own hash would have to be known before it was written.
write_release_manifest() {
  local root="$1"
  local out="$root/$RELEASE_MANIFEST_NAME"
  local list="$STAGE_ROOT/release-manifest-files"
  : > "$out" || return 1
  find "$root" -type f -print0 > "$list" || return 1
  local file relative digest
  while IFS= read -r -d '' file; do
    relative="${file#"$root/"}"
    relative="${relative//\\//}"
    [ "$relative" = "$RELEASE_MANIFEST_NAME" ] && continue
    validate_relative_path "$relative" || return 1
    digest="$(sha256_file "$file")" || return 1
    printf '%s  %s\n' "$digest" "$relative" >> "$out" || return 1
  done < "$list"
  [ -s "$out" ] || return 1
}

register_approved_prebuilt_path() {
  local relative="$1"
  if in_list "$relative" "${APPROVED_PREBUILT[@]}"; then
    return 0
  fi
  # The .NET runtime dependencies are a wildcard rather than a fixed list because the SDK decides
  # how many there are. Linux declares REQUIRE_DOTNET_DLLS=0 and therefore never reaches this arm,
  # so a stray DLL in a Linux prebuilt directory is rejected rather than silently shipped.
  if [ "$REQUIRE_DOTNET_DLLS" -eq 1 ]; then
    case "$relative" in
      dotnet/x64/*.dll)
        local name="${relative#dotnet/x64/}"
        case "$name" in
          */*|"") fail "unapproved prebuilt path: $relative" ;;
        esac
        DOTNET_DLL_PATHS+=("$relative")
        return 0
        ;;
    esac
  fi
  fail "unapproved prebuilt path: $relative"
}

validate_prebuilt_manifest() {
  [ -d "$PREBUILT" ] || fail "SHELLSIGHT_PREBUILT_DIR does not exist or is not a directory"
  [ -f "$PREBUILT_MANIFEST" ] || fail "missing required SHA-256 manifest: SHA256SUMS"
  [ ! -L "$PREBUILT_MANIFEST" ] || fail "SHA256SUMS must not be a symlink"

  local symlink_list="$STAGE_ROOT/prebuilt-symlinks"
  find "$PREBUILT" -type l -print -quit > "$symlink_list" || fail "cannot inspect prebuilt symlinks"
  [ ! -s "$symlink_list" ] || fail "prebuilt directory contains a symlink"

  local line digest relative key source actual
  local manifest_count=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^([0-9A-Fa-f]{64})[[:space:]][[:space:]]([^[:cntrl:]]+)$ ]] || fail "malformed SHA256SUMS line"
    digest="${BASH_REMATCH[1],,}"
    relative="${BASH_REMATCH[2]}"
    validate_relative_path "$relative"
    register_approved_prebuilt_path "$relative"
    key="${relative,,}"
    [ -z "${PREBUILT_HASHES[$key]+present}" ] || fail "duplicate prebuilt path / duplicate source manifest entry: $relative"
    source="$PREBUILT/$relative"
    [ -f "$source" ] || fail "manifest path is not a regular file: $relative"
    [ ! -L "$source" ] || fail "manifest path is a symlink: $relative"
    actual="$(sha256_file "$source")" || fail "cannot hash prebuilt file: $relative"
    [ "${actual,,}" = "$digest" ] || fail "prebuilt hash mismatch: $relative"
    PREBUILT_HASHES["$key"]="$digest"
    PREBUILT_PATHS["$key"]="$relative"
    manifest_count=$((manifest_count + 1))
  done < "$PREBUILT_MANIFEST"

  local required
  for required in "${REQUIRED_PREBUILT[@]}"; do
    [ -n "${PREBUILT_HASHES[${required,,}]+present}" ] || fail "missing required prebuilt asset: $required"
  done
  if [ "$REQUIRE_DOTNET_DLLS" -eq 1 ]; then
    [ "${#DOTNET_DLL_PATHS[@]}" -gt 0 ] || fail "missing required prebuilt asset: dotnet/x64/*.dll"
  fi

  local file_list="$STAGE_ROOT/prebuilt-files"
  # The manifest is excluded by NAME after the walk, not by `! -path "$PREBUILT_MANIFEST"`. -path
  # takes an fnmatch pattern, in which a backslash escapes the next character, so a Windows-style
  # SHELLSIGHT_PREBUILT_DIR made the pattern match nothing and SHA256SUMS was reported as an
  # unmanifested file -- aborting the run before any of this script's guards could be reached.
  # Measured 2026-09-04, alongside the coreutils escaping in sha256_file: same root cause, a path
  # holding a backslash, in the two places that pass one to another program's pattern syntax.
  find "$PREBUILT" -type f -print0 > "$file_list" || fail "cannot enumerate prebuilt files"
  local file file_relative file_key file_count=0
  while IFS= read -r -d '' file; do
    file_relative="${file#"$PREBUILT/"}"
    [ "$file_relative" != "SHA256SUMS" ] || continue
    file_key="${file_relative,,}"
    [ -n "${PREBUILT_HASHES[$file_key]+present}" ] || fail "unmanifested prebuilt file: $file_relative"
    file_count=$((file_count + 1))
  done < "$file_list"
  [ "$file_count" -eq "$manifest_count" ] || fail "SHA256SUMS does not cover every prebuilt file"
}

record_hash() {
  local destination="$1"
  local relative="$2"
  local expected="$3"
  local digest
  digest="$(sha256_file "$destination")" || return 1
  [ "${digest,,}" = "$expected" ] || {
    echo "[package] staged prebuilt hash mismatch: $relative" >&2
    return 1
  }
  printf '%s  %s\n' "$expected" "$relative" >> "$HASH_FILE" || return 1
}

stage_prebuilt_file() {
  local relative="$1"
  local stage_relative="$2"
  local source="$PREBUILT/$relative"
  local destination="$BIN/$stage_relative"
  local source_key="${relative,,}"
  local destination_key="${stage_relative,,}"
  local expected
  [ -n "${PREBUILT_HASHES[$source_key]+present}" ] || {
    echo "[package] unknown staged source: $relative" >&2
    return 1
  }
  [ -z "${STAGED_SOURCES[$source_key]+present}" ] || {
    echo "[package] duplicate staged source: $relative" >&2
    return 1
  }
  [ -z "${STAGED_EXPECTED_HASHES[$destination_key]+present}" ] || {
    echo "[package] duplicate staged destination: $stage_relative" >&2
    return 1
  }
  expected="${PREBUILT_HASHES[$source_key]}"
  mkdir -p "$(dirname "$destination")" || return 1
  cp "$source" "$destination" || return 1
  record_hash "$destination" "$stage_relative" "$expected" || return 1
  STAGED_EXPECTED_HASHES["$destination_key"]="$expected"
  STAGED_DESTINATIONS["$destination_key"]="$stage_relative"
  STAGED_SOURCES["$source_key"]="$stage_relative"
}

verify_staged_prebuilt_mapping() {
  [ "${#STAGED_EXPECTED_HASHES[@]}" -eq "${#PREBUILT_HASHES[@]}" ] || return 1
  [ "${#STAGED_SOURCES[@]}" -eq "${#PREBUILT_HASHES[@]}" ] || return 1
  local source_key destination destination_key expected actual
  for source_key in "${!PREBUILT_HASHES[@]}"; do
    destination="${STAGED_SOURCES[$source_key]:-}"
    [ -n "$destination" ] || return 1
    destination_key="${destination,,}"
    expected="${PREBUILT_HASHES[$source_key]}"
    [ "${STAGED_EXPECTED_HASHES[$destination_key]:-}" = "$expected" ] || return 1
    [ "${STAGED_DESTINATIONS[$destination_key]:-}" = "$destination" ] || return 1
    actual="$(sha256_file "$BIN/$destination")" || return 1
    [ "${actual,,}" = "$expected" ] || return 1
  done
}

run_package_test_hook() {
  local phase="$1"
  [ -n "${SHELLSIGHT_PACKAGE_TEST_HOOK:-}" ] || return 0
  [ "${SHELLSIGHT_PACKAGE_TEST_MODE:-}" = "1" ] || fail "package test hook requires SHELLSIGHT_PACKAGE_TEST_MODE=1"
  [ -f "$SHELLSIGHT_PACKAGE_TEST_HOOK" ] || fail "package test hook is not a file"
  "$SHELLSIGHT_PACKAGE_TEST_HOOK" "$phase" "$PREBUILT" "$BIN" "$VERIFY_DIR" "$FINAL_BIN" || fail "package test hook failed at $phase"
}

validate_prebuilt_manifest
run_package_test_hook "after-manifest-validation"

mkdir -p "$BIN" || fail "cannot create fresh package stage"
: > "$HASH_FILE" || fail "cannot create staged probe hash manifest"

echo "[package] verified required SHELLSIGHT_PREBUILT_DIR layout and SHA256SUMS ($TARGET)"
echo "[package] building literal Go shipping allowlist -> fresh stage"
# CGO_ENABLED=0 is not an optimisation: it is what makes the result a static ELF with no PT_INTERP
# and no versioned glibc symbols, which is in turn what lets ONE archive per architecture cover
# every distribution instead of one per distro family (research.md R1, contract A4.4).
for component in "${GO_COMPONENTS[@]}"; do
  staged="${component%%:*}"
  pkg="${component#*:}"
  GOOS="$TARGET_GOOS" GOARCH="$TARGET_GOARCH" CGO_ENABLED=0 \
    "$GO" -C "$ROOT" build -o "$BIN/$staged" "$pkg" || fail "$staged build failed"
done

echo "[package] staging knowledge base"
mkdir -p "$BIN/kb" || fail "cannot create staged knowledge-base directory"
cp -r "$ROOT/kb/." "$BIN/kb/" || fail "cannot stage knowledge base"
[ -f "$BIN/kb/rules/mem-contracts.json" ] || fail "staged mem-contracts.json is missing"

echo "[package] staging verified prebuilt runtime assets"
for mapping in "${PREBUILT_STAGING[@]}"; do
  stage_prebuilt_file "${mapping%%:*}" "${mapping#*:}" || fail "cannot stage ${mapping%%:*}"
done
if [ "$REQUIRE_DOTNET_DLLS" -eq 1 ]; then
  for relative in "${DOTNET_DLL_PATHS[@]}"; do
    stage_prebuilt_file "$relative" "${relative##*/}" || fail "cannot stage .NET dependency: $relative"
  done
fi
verify_staged_prebuilt_mapping || fail "staged prebuilt digest mapping failed"

VER="${SHELLSIGHT_VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
# ../docs/RUNBOOK.md: the runbook lives at the REPOSITORY root's docs/, not in the module, since it
# was grouped with the other operator documents. It still ships at the archive root, because that is
# where a responder who unpacked the archive will look for it.
cp "$ROOT/../docs/RUNBOOK.md" "$BIN/RUNBOOK.md" || fail "cannot stage RUNBOOK.md"
printf '%s\n' "$VER" > "$BIN/VERSION" || fail "cannot stage VERSION"

# The component declaration a generator assembles from: which files each view needs, per target.
#
# Emitted from cmd/shellsight/registry.go rather than restated here. This script already keeps its
# own per-target staged lists, and a second hand-maintained list of view -> components is precisely
# the drift the declaration exists to prevent -- the same reason internal/weblang exists.
#
# Built and run for the BUILD HOST even on a cross-package run. GOOS/GOARCH are in this script's
# environment -- that is how a target is selected -- and would otherwise produce a linux-arm64
# emitter this box cannot execute. Cleared rather than set to the host's values: cmd/go reads an
# EMPTY GOOS/GOARCH as unset and falls back to the host, so no `go env` round trip is needed to
# learn what this machine is.
#
# The document is still the TARGET's, from the two arguments below. The platform it runs on and the
# platform it describes are unrelated, which is the whole reason componentsDoc is a pure function of
# the table.
GOOS= GOARCH= CGO_ENABLED=0 \
  "$GO" -C "$ROOT" run ./cmd/shellsight components \
    -target "$TARGET" -goos "$TARGET_GOOS" -release "$VER" \
    -out "$BIN/components.json" || fail "cannot emit components.json"
[ -s "$BIN/components.json" ] || fail "staged components.json is empty"

verify_no_forbidden_files() {
  local root="$1"
  local list="$STAGE_ROOT/forbidden-scan"
  find "$root" -type f -print0 > "$list" || return 1
  local file relative
  while IFS= read -r -d '' file; do
    relative="${file#"$root/"}"
    if is_forbidden_release_path "$relative"; then
      echo "[package] forbidden development or lab binary: $relative" >&2
      return 1
    fi
  done < "$list"
}

verify_no_forbidden_files "$BIN" || fail "development tool leaked into release stage"

# WHERE THE ARCHIVE GOES, and why it is not the module root any more.
#
# It used to be `$ROOT/shellsight-$VER-...`, and the `rm -f` below clears only an archive of the
# SAME name -- so every run with a new `git describe` left the previous one behind. Three package
# runs put 243 MB of superseded archives in the module root next to the source, where nothing
# pruned them because they are all gitignored. `release/` gives them one place to live, one place
# to clean, and stops `ls` in the module root being mostly build output.
#
# The FILENAME convention is unchanged, deliberately: `platform_matrix.py` reads the swept revision
# off the archive name (`-v1.0.0-139-gf39c9d2-` -> f39c9d2) and V13 depends on it. Only the
# directory moved.
RELEASE_DIR="${SHELLSIGHT_RELEASE_DIR:-$ROOT/release}"
mkdir -p "$RELEASE_DIR" || fail "cannot create the release output directory"
ZIP="$RELEASE_DIR/shellsight-$VER-$ARCHIVE_SUFFIX"
rm -f "$ZIP" "$ZIP.sha256" || fail "cannot clear prior archive outputs"

# create_tar_gz writes the tarball in TWO passes, executables first.
#
# Why two: this build host is Windows, and NTFS through Git Bash does not carry a POSIX execute
# bit -- measured, `tar -tvzf` reported -rw-r--r-- on a file chmod'ed 755. A single-pass tar would
# therefore ship components that are not executable as unpacked, breaking contract A4.1 in a way
# nobody notices until a responder runs it on the target host. GNU tar's --mode is global, so the
# two classes are written separately: 0755 for components, and a SYMBOLIC a+rX for everything else
# so that data files stay 0644 while directories keep the traversal bit they need (a literal 0644
# here makes kb/ unenterable -- also measured).
#
# The passes are driven by EXPLICIT FILE LISTS rather than by top-level globs. The glob version
# shipped the engine at 0644 because third_party/ went into the data pass as a whole directory, and
# that one wrong bit took down the entire scan.
#
# --owner/--group/--numeric-owner drop this box's account out of the distributed archive;
# --sort=name plus a sorted list makes the member order reproducible and puts every directory ahead
# of its contents; --no-recursion stops the directory entries from re-adding what the lists already
# name.
create_tar_gz() {
  local out="$1" root="$2"
  local all="$STAGE_ROOT/tar-all" exec_list="$STAGE_ROOT/tar-exec" data_list="$STAGE_ROOT/tar-data"
  local rel e

  for e in "${EXECUTABLE_STAGED[@]}"; do
    [ -f "$root/$e" ] || { echo "[package] declared executable missing from stage: $e" >&2; return 1; }
  done

  ( cd "$root" && find . -mindepth 1 \( -type f -o -type d \) ) | sed 's|^\./||' | LC_ALL=C sort > "$all" || return 1
  : > "$exec_list" || return 1
  : > "$data_list" || return 1
  while IFS= read -r rel; do
    if in_list "$rel" "${EXECUTABLE_STAGED[@]}"; then
      printf '%s\n' "$rel" >> "$exec_list"
    else
      printf '%s\n' "$rel" >> "$data_list"
    fi
  done < "$all"

  [ -s "$exec_list" ] || { echo "[package] no executable members to archive" >&2; return 1; }
  [ "$(grep -c . "$exec_list")" -eq "${#EXECUTABLE_STAGED[@]}" ] || {
    echo "[package] executable list does not match the declared set" >&2; return 1; }

  rm -f "$out.tar" "$out.tar.gz" || return 1
  tar --mode=0755 --owner=0 --group=0 --numeric-owner --no-recursion \
      -cf "$out.tar" -C "$root" -T "$exec_list" || return 1
  tar --mode='a+rX,u+w,go-w' --owner=0 --group=0 --numeric-owner --no-recursion \
      -rf "$out.tar" -C "$root" -T "$data_list" || return 1
  gzip -n -9 "$out.tar" || return 1
  mv "$out.tar.gz" "$out" || return 1
}

# The inventory is written LAST, after every component is staged and before anything is archived:
# it must describe the stage exactly as the archive will carry it.
write_release_manifest "$BIN" || fail "cannot write $RELEASE_MANIFEST_NAME"

case "$ARCHIVE_KIND" in
  zip)
    powershell -NoProfile -NonInteractive -Command \
      "\$items = Get-ChildItem -LiteralPath '$(cygpath -w "$BIN")';
       Compress-Archive -Path \$items.FullName -DestinationPath '$(cygpath -w "$ZIP")' -Force" \
      || fail "archive creation failed"
    ;;
  tar.gz)
    # Every Go component must be in the declared executable set; the set may legitimately hold more
    # (the engine). Checked rather than assumed, because the engine's absence from it is exactly the
    # bug this guards.
    for component in "${GO_COMPONENTS[@]}"; do
      in_list "${component%%:*}" "${EXECUTABLE_STAGED[@]}" \
        || fail "component ${component%%:*} is not in EXECUTABLE_STAGED"
    done
    create_tar_gz "$ZIP" "$BIN" || fail "archive creation failed"
    ;;
  *)
    fail "unknown archive kind: $ARCHIVE_KIND"
    ;;
esac
[ -s "$ZIP" ] || fail "archive creation produced an empty file"

ZIP_RECORDED_SHA256="$(sha256_file "$ZIP")" || fail "cannot hash created archive"
# "<hash>  <basename>", the coreutils format, so the recipient can run the obvious command:
#
#   sha256sum -c shellsight-<version>-linux-amd64.tar.gz.sha256
#
# It used to be the bare digest with no filename, which `sha256sum -c` rejects outright -- "no
# properly formatted SHA256 checksum lines found" -- while README.md told analysts to run exactly
# that. Shipping a verification file that cannot be verified with the documented command is worse
# than shipping none, because it teaches the recipient to skip the check.
#
# The BASENAME, not the path: the file sits beside the archive, and `-c` resolves relative to the
# working directory.
printf '%s  %s\n' "$ZIP_RECORDED_SHA256" "$(basename "$ZIP")" > "$ZIP.sha256" \
  || fail "cannot record archive SHA-256"
ZIP_MANIFEST_SHA256="$(cut -d' ' -f1 < "$ZIP.sha256" | tr -d '\r\n ')" || fail "cannot read recorded archive SHA-256"
ZIP_VERIFIED_SHA256="$(sha256_file "$ZIP")" || fail "cannot recompute archive SHA-256"
[ "$ZIP_RECORDED_SHA256" = "$ZIP_MANIFEST_SHA256" ] || fail "recorded archive SHA-256 does not match hash file"
[ "$ZIP_RECORDED_SHA256" = "$ZIP_VERIFIED_SHA256" ] || fail "recomputed archive SHA-256 mismatch"

# Validate entry names before extraction so an absolute/traversing entry never
# reaches the verification filesystem.
case "$ARCHIVE_KIND" in
  zip)
    powershell -NoProfile -NonInteractive -Command \
      "Add-Type -AssemblyName System.IO.Compression.FileSystem;
       \$archive = [System.IO.Compression.ZipFile]::OpenRead('$(cygpath -w "$ZIP")');
       try {
         foreach (\$entry in \$archive.Entries) {
           \$name = \$entry.FullName.Replace('\\','/');
           if (\$name.StartsWith('/') -or \$name -match '^[A-Za-z]:') { throw ('archive entry is absolute: ' + \$name) }
           if (\$name.Split('/') -contains '..') { throw ('archive entry traverses: ' + \$name) }
         }
       } finally { \$archive.Dispose() }" \
      || fail "archive entry-name verification failed"
    ;;
  tar.gz)
    # Same property, same order: names are checked from the listing BEFORE anything is written to
    # the filesystem. A tarball additionally has to be refused if it carries a link, because a
    # symlink member is how an archive escapes its extraction directory on unpack.
    tar -tzf "$ZIP" > "$STAGE_ROOT/archive-entries" || fail "cannot list archive entries"
    tar -tvzf "$ZIP" > "$STAGE_ROOT/archive-listing" || fail "cannot list archive members"
    while IFS= read -r entry_name || [ -n "$entry_name" ]; do
      case "$entry_name" in
        /*|[A-Za-z]:*) fail "archive entry is absolute: $entry_name" ;;
        ../*|*/../*|*/..) fail "archive entry traverses: $entry_name" ;;
      esac
    done < "$STAGE_ROOT/archive-entries"
    # A link member is how a tarball escapes its extraction directory on unpack, so refuse both
    # kinds outright rather than relying on the extractor to be careful.
    if grep -qE '^[hl]' "$STAGE_ROOT/archive-listing"; then
      fail "archive contains a hard link or symlink entry"
    fi
    ;;
esac

mkdir -p "$VERIFY_DIR" || fail "cannot create fresh archive verification directory"
case "$ARCHIVE_KIND" in
  zip)
    powershell -NoProfile -NonInteractive -Command \
      "Expand-Archive -LiteralPath '$(cygpath -w "$ZIP")' -DestinationPath '$(cygpath -w "$VERIFY_DIR")' -Force" \
      || fail "archive extraction verification failed"
    ;;
  tar.gz)
    tar -xzf "$ZIP" -C "$VERIFY_DIR" || fail "archive extraction verification failed"
    # Contract A4.1: every component must be executable AS UNPACKED. Asserted from the archive's own
    # recorded modes rather than from the extracted files, because this host's filesystem cannot
    # represent the bit and would report whatever it likes.
    for staged in "${EXECUTABLE_STAGED[@]}"; do
      grep -qE "^-rwxr-xr-x .* $staged\$" "$STAGE_ROOT/archive-listing" \
        || fail "archive member is not executable as unpacked: $staged"
    done
    # And the converse: nothing else may carry the execute bit into a responder's filesystem.
    while IFS= read -r listed; do
      case "$listed" in
        -rwx*)
          member="${listed##* }"
          in_list "$member" "${EXECUTABLE_STAGED[@]}" \
            || fail "unexpected executable member: $member"
          ;;
      esac
    done < "$STAGE_ROOT/archive-listing"
    ;;
esac
run_package_test_hook "after-extract-before-verification"

verify_required_archive_assets() {
  local root="$1"
  local required
  for required in "${REQUIRED_ARCHIVE[@]}"; do
    [ -f "$root/$required" ] || {
      echo "[package] required archive asset missing: $required" >&2
      return 1
    }
  done
  if [ "$REQUIRE_DOTNET_DLLS" -eq 1 ]; then
    local dependency_count=0 dependency
    for dependency in "$root"/*.dll; do
      [ -f "$dependency" ] || continue
      dependency_count=$((dependency_count + 1))
    done
    [ "$dependency_count" -gt 0 ] || {
      echo "[package] required .NET dependency assets are missing" >&2
      return 1
    }
  else
    # A Linux archive must not carry Windows components at all -- an inert dotnetmem.exe in the
    # tarball would be a capability claim the runtime cannot honour (contract A2).
    local stray
    for stray in "$root"/*.dll "$root"/*.exe; do
      [ -e "$stray" ] || continue
      echo "[package] Windows component in a $TARGET archive: ${stray#"$root/"}" >&2
      return 1
    done
  fi
}

is_approved_extracted_prebuilt_path() {
  local relative="$1"
  if in_list "$relative" "${APPROVED_STAGED[@]}"; then
    return 0
  fi
  if [ "$REQUIRE_DOTNET_DLLS" -eq 1 ]; then
    case "$relative" in
      *.dll)
        case "$relative" in
          */*) return 1 ;;
        esac
        return 0
        ;;
    esac
  fi
  return 1
}

verify_extracted_prebuilt_hashes() {
  local root="$1"
  local manifest="$root/PROBE-HASHES.sha256"
  local line digest relative key source actual count=0 expected
  local -A seen=()
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^([0-9A-Fa-f]{64})[[:space:]][[:space:]]([^[:cntrl:]]+)$ ]] || return 1
    digest="${BASH_REMATCH[1],,}"
    relative="${BASH_REMATCH[2]}"
    validate_relative_path "$relative"
    is_approved_extracted_prebuilt_path "$relative" || return 1
    key="${relative,,}"
    [ -z "${seen[$key]+present}" ] || return 1
    [ -n "${STAGED_EXPECTED_HASHES[$key]+present}" ] || return 1
    [ "${STAGED_DESTINATIONS[$key]}" = "$relative" ] || return 1
    expected="${STAGED_EXPECTED_HASHES[$key]}"
    [ "$digest" = "$expected" ] || return 1
    source="$root/$relative"
    [ -f "$source" ] || return 1
    actual="$(sha256_file "$source")" || return 1
    [ "${actual,,}" = "$expected" ] || return 1
    seen["$key"]=1
    count=$((count + 1))
  done < "$manifest"
  [ "$count" -eq "${#STAGED_EXPECTED_HASHES[@]}" ] || return 1
  for key in "${!STAGED_EXPECTED_HASHES[@]}"; do
    [ -n "${seen[$key]+present}" ] || return 1
  done
}

# verify_extracted_release_manifest asserts the shipped inventory names EXACTLY the files shipped.
#
# The producer checking its own output, so this script cannot emit a release its own consumer would
# refuse. Both directions are checked, because only both together are the property that matters:
# every manifested path must exist with the recorded hash, and every extracted file except the
# manifest itself must be named.
verify_extracted_release_manifest() {
  local root="$1"
  local manifest="$root/$RELEASE_MANIFEST_NAME"
  [ -f "$manifest" ] || return 1
  local line digest relative key actual file
  local -A named=()
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [ -n "$line" ] || continue
    [[ "$line" =~ ^([0-9A-Fa-f]{64})[[:space:]][[:space:]]([^[:cntrl:]]+)$ ]] || return 1
    digest="${BASH_REMATCH[1],,}"
    relative="${BASH_REMATCH[2]}"
    validate_relative_path "$relative" || return 1
    key="${relative,,}"
    [ -z "${named[$key]+present}" ] || return 1
    [ -f "$root/$relative" ] || return 1
    actual="$(sha256_file "$root/$relative")" || return 1
    [ "${actual,,}" = "$digest" ] || return 1
    named["$key"]=1
  done < "$manifest"
  local list="$STAGE_ROOT/extracted-release-files"
  find "$root" -type f -print0 > "$list" || return 1
  while IFS= read -r -d '' file; do
    relative="${file#"$root/"}"
    relative="${relative//\\//}"
    [ "$relative" = "$RELEASE_MANIFEST_NAME" ] && continue
    [ -n "${named[${relative,,}]+present}" ] || {
      echo "[package] $RELEASE_MANIFEST_NAME does not name $relative" >&2
      return 1
    }
  done < "$list"
}

verify_extracted_runtime_dlls() {
  local root="$1"
  # Nothing to check on a target that ships no .NET runtime: the stray-component check inside
  # verify_required_archive_assets already refuses a DLL that appears anyway.
  [ "$REQUIRE_DOTNET_DLLS" -eq 1 ] || return 0
  local list="$STAGE_ROOT/extracted-runtime-dlls"
  find "$root" -type f -iname '*.dll' -print0 > "$list" || return 1
  local file relative key expected actual destination
  local -A seen=()
  while IFS= read -r -d '' file; do
    relative="${file#"$root/"}"
    case "$relative" in
      */*)
        echo "[package] runtime DLL staged outside root: $relative" >&2
        return 1
        ;;
    esac
    key="${relative,,}"
    [ -n "${STAGED_EXPECTED_HASHES[$key]+present}" ] || {
      echo "[package] unexpected runtime DLL: $relative" >&2
      return 1
    }
    destination="${STAGED_DESTINATIONS[$key]}"
    case "$destination" in
      *.dll) ;;
      *)
        echo "[package] unexpected runtime DLL: $relative" >&2
        return 1
        ;;
    esac
    [ "$relative" = "$destination" ] || {
      echo "[package] runtime DLL name is not canonical: $relative" >&2
      return 1
    }
    [ -z "${seen[$key]+present}" ] || {
      echo "[package] duplicate runtime DLL: $relative" >&2
      return 1
    }
    expected="${STAGED_EXPECTED_HASHES[$key]}"
    actual="$(sha256_file "$file")" || return 1
    [ "${actual,,}" = "$expected" ] || {
      echo "[package] runtime DLL hash mismatch: $relative" >&2
      return 1
    }
    seen["$key"]=1
  done < "$list"
  for key in "${!STAGED_EXPECTED_HASHES[@]}"; do
    destination="${STAGED_DESTINATIONS[$key]}"
    case "$destination" in
      *.dll)
        [ -n "${seen[$key]+present}" ] || {
          echo "[package] missing runtime DLL: $destination" >&2
          return 1
        }
        ;;
    esac
  done
}

# verify_release_declaration is the one check that compares what a release SAYS against what it
# HOLDS.
#
# components.json is rendered from the capability table, and the table declares OPTIONAL views
# unconditionally: java-mem and dotnet-mem-x86 are in every document for their platform whether or
# not this build produced them. Without this, a release assembled on a box with no .NET toolchain
# would ship a declaration promising a dotnetmem-x86.exe the archive does not hold, and a console
# reading it would generate an agent that cannot run a view it was told it had. Nothing downstream
# could detect that: the document looks exactly like a correct one.
#
# Run against the EXTRACTED archive rather than the stage, and reading the document out of that same
# extraction rather than re-rendering it. Two reasons, both of them the difference between checking
# the artifact and checking our intentions. The archive is what a responder receives and it can hold
# LESS than the stage did -- Compress-Archive writes no entry for a directory with no files under it,
# so a declared-but-empty kb/rules/foundation is present in the stage and absent from the zip. And
# re-rendering would ask whether this source tree agrees with that directory, leaving the one file
# the console actually reads, the components.json inside the archive, unexamined.
#
# Not a restatement of REQUIRED_ARCHIVE, though today the two overlap on most of the Windows list.
# Measured 2026-09-04 by removing components from an extracted archive one at a time: the entries
# only this check covers are kb/rules/foundation and kb/rules/own -- and REQUIRED_ARCHIVE cannot
# ever cover those, because it tests -f and they are directories. That overlap is also a property of
# today's lists rather than a guarantee: REQUIRED_ARCHIVE is maintained by hand here, the
# declaration is generated from the table, and nothing keeps them in step.
verify_release_declaration() {
  local root="$1"
  GOOS= GOARCH= CGO_ENABLED=0 \
    "$GO" -C "$ROOT" run ./cmd/shellsight components -verify "$root"
}

verify_required_archive_assets "$VERIFY_DIR" || fail "archive is incomplete"
verify_no_forbidden_files "$VERIFY_DIR" || fail "forbidden file found in extracted archive"
verify_extracted_prebuilt_hashes "$VERIFY_DIR" || fail "extracted prebuilt hash verification failed"
verify_extracted_release_manifest "$VERIFY_DIR" || fail "the release inventory does not match the archive"
verify_extracted_runtime_dlls "$VERIFY_DIR" || fail "extracted runtime DLL verification failed"
verify_release_declaration "$VERIFY_DIR" || fail "the release declaration does not match the archive"

# preserve_operator_state carries operator-owned content from the previous install into the new one.
#
# It runs AFTER the archive has been built and verified from the stage, which is the whole point:
# these paths must reach the local bin/ and must never enter a distributable zip, or one site's
# rules and forensic artifacts would ship to whoever receives the release.
#
# Measured 2026-08-10 by planting files and upgrading: every one of these was destroyed.
#   kb/rules/custom  the analyst's own detection rules
#   lab              the benign corpus, whose absence makes `rules validate` return 3 not 0
#   artifacts        decompiled Java/.NET memshell source from earlier scans — evidence
#
# Contents are merged (`cp -r src/. dst/`) rather than moved wholesale, so a future release that
# ships one of these paths would be added to rather than replaced.
preserve_operator_state() {
  local from="$1" to="$2" rel
  for rel in kb/rules/custom lab artifacts; do
    [ -e "$from/$rel" ] || continue
    mkdir -p "$to/$rel" || return 1
    cp -r "$from/$rel/." "$to/$rel/" || return 1
    echo "[package] preserved $rel/ from the previous install"
  done
}

# Replace bin/ only after all stage, ZIP hash, entry-name, extraction, required
# asset, forbidden-name, and extracted prebuilt hash checks have passed.
mkdir -p "$(dirname "$FINAL_BIN")" || fail "cannot create the install parent directory"
had_previous=0
if [ -e "$FINAL_BIN" ]; then
  mv "$FINAL_BIN" "$OLD_BIN" || fail "cannot preserve existing bin directory"
  had_previous=1
fi
mv "$BIN" "$FINAL_BIN" || {
  if [ "$had_previous" -eq 1 ]; then
    mv "$OLD_BIN" "$FINAL_BIN" || fail "release install failed and existing bin could not be restored"
  fi
  fail "failed to install verified release stage"
}
if [ "$had_previous" -eq 1 ]; then
  # Only bin/ is an INSTALL that an operator puts custom rules and forensic artifacts into. A
  # cross-compiled dist/ tree is a build output, and carrying content forward inside one would
  # quietly reintroduce state into something whose only job is to be reproducible from source.
  if [ "$FINAL_BIN" = "$ROOT/bin" ]; then
    preserve_operator_state "$OLD_BIN" "$FINAL_BIN" || fail "cannot preserve operator state across upgrade"
  fi
  rm -rf "$OLD_BIN" || fail "cannot remove replaced bin backup"
fi

# Prune superseded archives for THIS TARGET, and only now.
#
# Placed after the stage, hash, entry-name, extraction, required-asset, forbidden-name and
# extracted-prebuilt checks have all passed and bin/ has been installed. A prune that ran earlier
# would delete a good previous archive on the way to failing, leaving nothing shippable at all.
#
# SCOPED BY ARCHIVE SUFFIX, so packaging windows-amd64 cannot touch a linux-arm64 archive: the
# three targets are built by three separate invocations and each must leave the others alone.
# Scoped by the `-v<version>-` shape too, so an unrelated file that happens to sit in release/ is
# not swept up by a glob.
# A DIRTY BUILD MUST NOT PRUNE A CLEAN ARCHIVE. Found by running this the first time: the tree was
# dirty, so `git describe` named the new archive `...-gcc36032-dirty-win.zip`, and the prune
# cheerfully deleted the clean `...-gcc36032-win.zip` it superseded. A dirty archive is not a
# release -- `dirty` is precisely the marker that says a build is not attributable to a commit -- so
# trading a clean one for it is the wrong direction. Dirty builds keep everything.
if [ "${SHELLSIGHT_KEEP_OLD_ARCHIVES:-0}" != "1" ] && [ "${VER#*-dirty}" = "$VER" ]; then
  pruned=0
  for old_archive in "$RELEASE_DIR"/shellsight-v*-"$ARCHIVE_SUFFIX"; do
    [ -e "$old_archive" ] || continue
    [ "$old_archive" = "$ZIP" ] && continue
    rm -f "$old_archive" "$old_archive.sha256" || fail "cannot prune superseded archive"
    echo "[package] pruned superseded -> $(basename "$old_archive")"
    pruned=$((pruned + 1))
  done
  [ "$pruned" -gt 0 ] && echo "[package] pruned $pruned superseded $ARCHIVE_SUFFIX archive(s); SHELLSIGHT_KEEP_OLD_ARCHIVES=1 to retain"
elif [ "${VER#*-dirty}" != "$VER" ]; then
  echo "[package] dirty build -- keeping all existing $ARCHIVE_SUFFIX archives"
fi

echo "[package] done -> $FINAL_BIN"
echo "[package] done -> $ZIP (+ .sha256)"
