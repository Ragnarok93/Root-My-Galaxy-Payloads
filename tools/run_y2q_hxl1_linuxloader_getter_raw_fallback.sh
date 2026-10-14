#!/usr/bin/env bash
# Read-only fallback for cancelled HXL1 LinuxLoader Ghidra getter queries.
# Reuses exact original local PE and most recently written two-getter callsites.
# No REA/Ghidra, no device connection, and no firmware modification.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="${HXL1_RESEARCH_ROOT:-$HOME/s20-artifacts/hxl1-research}"
LOADER="${HXL1_LOADER:-$ROOT/abl-linuxloader/LinuxLoader-HXL1.efi}"
CALLSITES="${1:-}"

if test -z "$CALLSITES"; then
  test -d "$ROOT"
  latest="$(find "$ROOT" -maxdepth 3 -type f -name callsite-evidence.json \
      -path '*/targeted-dtb-dtbo-getters-*/callsite-evidence.json' \
      -printf '%T@ %p\n' | sort -rn | head -n1 || true)"
  test -n "$latest" || {
    echo "[STOP] No saved two-getter callsite-evidence.json under $ROOT" >&2
    exit 2
  }
  CALLSITES="${latest#* }"
fi

test -f "$CALLSITES" && test ! -L "$CALLSITES"
test -f "$LOADER" && test ! -L "$LOADER"
OUT="$(dirname "$CALLSITES")/getter-raw-native-windows-$(date -u +%Y%m%dT%H%M%SZ).json"
test ! -e "$OUT"

python3 -m tools.y2q_hxl1_linuxloader_getter_raw_windows \
  --loader "$LOADER" --callsites "$CALLSITES" --output "$OUT"

echo "[NO REA OR Ghidra CALLS]"
echo "[STAGE 4 SELECTOR / PHYSICAL HANDOFF] STILL UNVERIFIED"
