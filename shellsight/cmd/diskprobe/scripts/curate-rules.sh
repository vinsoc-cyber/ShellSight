#!/usr/bin/env bash
# curate-rules.sh — fetch + compile-validate the bundled disk webshell rule pack.
# License-clean source only: Neo23x0/signature-base thor-webshells.yar (DRL-1.1).
# Re-runnable; writes its output to kb/rules/foundation/ for committing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"   # -> shellsight/
FOUNDATION="$REPO_ROOT/kb/rules/foundation"
YR="${SHELLSIGHT_YR:-$REPO_ROOT/bin/third_party/yara-x/yr.exe}"
SRC_URL="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar"
PACK="$FOUNDATION/signature-base-thor-webshells.yar"

mkdir -p "$FOUNDATION"
echo "[curate] downloading thor-webshells.yar ..."
curl -fSL --max-time 120 -o "$PACK.tmp" "$SRC_URL"
if [ ! -s "$PACK.tmp" ]; then
  echo "[curate] ERROR: download empty (AV quarantine or network block?)"; rm -f "$PACK.tmp"; exit 1
fi
rules=$(grep -c '^rule ' "$PACK.tmp" || true)
echo "[curate] downloaded $rules rules"

# Compile-validate under yara-x: must exit 0 (warnings are fine, errors are not).
if [ -f "$YR" ]; then
  echo "harmless" > "$FOUNDATION/.curate_dummy.txt"
  if ! "$YR" scan "$PACK.tmp" "$FOUNDATION/.curate_dummy.txt" >/dev/null 2>"$FOUNDATION/.curate_err.txt"; then
    echo "[curate] ERROR: pack failed to compile under yara-x:"; cat "$FOUNDATION/.curate_err.txt"
    rm -f "$PACK.tmp" "$FOUNDATION/.curate_dummy.txt" "$FOUNDATION/.curate_err.txt"; exit 1
  fi
  rm -f "$FOUNDATION/.curate_dummy.txt" "$FOUNDATION/.curate_err.txt"
  echo "[curate] yara-x compile OK"
else
  echo "[curate] WARN: yr not found at $YR — skipping compile validation"
fi

mv -f "$PACK.tmp" "$PACK"
date -u +%Y%m%d > "$FOUNDATION/VERSION"
cat > "$FOUNDATION/SOURCES.md" <<EOF
# Bundled disk rule pack — sources & attribution

| File | Source | License | Notes |
|---|---|---|---|
| signature-base-thor-webshells.yar | https://github.com/Neo23x0/signature-base (yara/thor-webshells.yar) | DRL-1.1 | ${rules} webshell rules; attribution-on-match required (each rule's \`author\` meta is surfaced in ShellSight findings) |

DRL-1.1 (Detection Rule License) permits use / modify / distribute / sell with attribution.
Regenerate this pack: \`cmd/diskprobe/scripts/curate-rules.sh\`
EOF
echo "[curate] wrote $PACK + VERSION + SOURCES.md"
