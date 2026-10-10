#!/usr/bin/env bash
# Original HXL1 EnvDxe: one Ghidra entrypoint dossier and 3 targeted strings.
# No phone access, no REA executable generation or firmware re-extraction.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
EXPECTED=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== Offline provenance regression suite ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_envdxe_entry_strings.py

echo "=== Original EnvDxe and verified zero-xrefs precondition ==="
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Original EnvDxe ELF or REA fork missing" >&2
  exit 2
}
echo "$EXPECTED  $EFI" | sha256sum -c --status || {
  echo "[STOP] EnvDxe PE no longer matches pinned original" >&2
  exit 2
}
python3 tools/y2q_hxl1_envdxe_rea_xrefs.py --out "$OUT" --verify-only

if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
  hash -r
fi
ENV="$HOME/s20-artifacts/hxl1-research/abl-linuxloader/rea-ghidra-env.sh"
if [[ -s "$ENV" ]]; then
  # shellcheck source=/dev/null
  . "$ENV"
fi
node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24 ? 0:1)' || {
  echo "[STOP] Node 24 required for the pinned REA/Ghidra workflow" >&2
  exit 2
}

ENTRY="$(python3 - "$OUT" <<'PY'
import sys
from pathlib import Path
from tools.y2q_hxl1_envdxe_entry_strings import entry_address
print(entry_address(Path(sys.argv[1])))
PY
)"
[[ "$ENTRY" =~ ^0x[[:xdigit:]]+$ ]] || {
  echo "[STOP] Invalid original EnvDxe PE entrypoint coordinate" >&2; exit 2;
}
ENTRY_OUT="$OUT/rea-envdxe-entry-function.json"
if python3 tools/y2q_hxl1_envdxe_entry_strings.py --out "$OUT" \
     --verify-single entry >/dev/null 2>&1; then
  echo "[REUSE] Original EnvDxe entrypoint function dossier"
else
  echo "[GHIDRA FUNCTION] Original EnvDxe PE entrypoint $ENTRY"
  # Only replace an absent evidence file; existing invalid or partial
  # results must not be silently overwritten.
  [[ ! -e "$ENTRY_OUT" ]] || {
    echo "[STOP] Existing invalid Ghidra entry evidence: $ENTRY_OUT" >&2; exit 2;
  }
  TMP="$OUT/rea-envdxe-entry-function.partial.json"
  [[ ! -e "$TMP" ]] || {
    echo "[STOP] Previous partial Ghidra entry evidence: $TMP" >&2; exit 2;
  }
  node "$REA" function "$EFI" "$ENTRY" --provider ghidra --json \
      > "$TMP" 2> "$OUT/rea-envdxe-entry-function-stderr.txt" || {
    echo "[STOP] Ghidra entry analysis failed; inspect $TMP and stderr" >&2; exit 2;
  }
  mv "$TMP" "$ENTRY_OUT"
  python3 tools/y2q_hxl1_envdxe_entry_strings.py --out "$OUT" --verify-single entry
fi

echo "=== Three targeted original Ghidra diagnostic string searches ==="
while IFS='|' read -r label term; do
  f="$OUT/rea-envdxe-search-$label.json"
  if python3 tools/y2q_hxl1_envdxe_entry_strings.py --out "$OUT" \
       --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Verified original Ghidra strings for $term"
    continue
  fi
  [[ ! -e "$f" ]] || {
    echo "[STOP] Existing invalid original Ghidra search evidence: $f" >&2
    exit 2
  }
  tmp="$OUT/rea-envdxe-search-$label.partial.json"
  [[ ! -e "$tmp" ]] || {
    echo "[STOP] Existing partial Ghidra search: $tmp" >&2
    exit 2
  }
  echo "[GHIDRA STRINGS] $term"
  node "$REA" search "$EFI" "$term" --kind strings --provider ghidra --json \
       > "$tmp" 2> "$OUT/rea-envdxe-search-$label-stderr.txt" || {
    echo "[STOP] REA Ghidra strings command failed; see $tmp and stderr" >&2
    exit 2
  }
  mv "$tmp" "$f"
  python3 tools/y2q_hxl1_envdxe_entry_strings.py --out "$OUT" \
     --verify-single "$label"
done <<'TERMS'
ram-partition|RamPartition
get-ram-partitions|GetRamPartitions
env-driver|EnvDxe
TERMS

python3 tools/y2q_hxl1_envdxe_entry_strings.py --out "$OUT"
cat "$OUT/rea-envdxe-entry-strings-audit.md"
echo "[LIMIT] String/entry evidence does not prove provider registration or live kernel PA"
