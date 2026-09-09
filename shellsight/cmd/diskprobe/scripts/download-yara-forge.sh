#!/usr/bin/env bash
# Downloads a YARA Forge rule package from GitHub Releases.
# Usage: ./download-yara-forge.sh [output-dir]   (tier via YARA_FORGE_TIER=core|extended|full)
# Default tier = core: curated, permissive licenses, low-FP -> the bundleable/resellable tier
# (measured 2026-06-16: +2-4pp JSP/ASPX recall at 0 FP cost). full = max breadth, more FP/license risk.
# The output dir becomes kb/rules/foundation/yara-forge/
# After download, rules live at: <output-dir>/packages/<tier>/yara-rules-<tier>.yar
set -euo pipefail
OUT="${1:-kb/rules/foundation/yara-forge}"
TIER="${YARA_FORGE_TIER:-core}"
mkdir -p "$OUT"

echo "Fetching latest YARA Forge release..."
RELEASE=$(curl -sf "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest")

# Support py (Windows), python3 (Linux/macOS), python (fallback)
PY=python3
command -v python3 >/dev/null 2>&1 || { command -v py >/dev/null 2>&1 && PY=py; } || PY=python

TAG=$(echo "$RELEASE" | $PY -c "import sys,json; r=json.load(sys.stdin); print(r['tag_name'])")
ASSET_URL=$(echo "$RELEASE" | $PY -c "
import sys,json
r=json.load(sys.stdin)
for a in r['assets']:
    if '$TIER' in a['name'] and a['name'].endswith('.zip'):
        print(a['browser_download_url']); break
")

echo "Downloading YARA Forge $TAG: $ASSET_URL"
curl -L "$ASSET_URL" -o "$OUT/yara-forge-rules.zip"
cd "$OUT" && unzip -o yara-forge-rules.zip && rm yara-forge-rules.zip

# Write VERSION to the foundation/ layer directory so 'shellsight rules list' can display it.
echo "$TAG" > "$(dirname "$OUT")/VERSION"
echo "YARA Forge $TAG installed to $OUT"
echo "Rules file: $OUT/packages/$TIER/yara-rules-$TIER.yar"
