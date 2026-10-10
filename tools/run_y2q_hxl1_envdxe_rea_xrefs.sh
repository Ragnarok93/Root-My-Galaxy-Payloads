#!/usr/bin/env bash
# Original HXL1 EnvDxe from original hash-pinned xbl.elf; REA xrefs only.
# Extracts one original module on host; no flashing, root, ADB or execution.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
REA="$HOME/src/rea/scripts/rea.mjs"
EFI="$OUT/EnvDxe-HXL1.efi"
EVIDENCE="$OUT/rea-envdxe-ram-guid-xrefs.json"

echo "=== Synthetic original EnvDxe PE and GUID-xref fixtures ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_extract_envdxe.py \
  tools/test_y2q_hxl1_envdxe_rea_xrefs.py

echo "=== Recover only original HXL1 EnvDxe, exact SHA256 and FFS provenance ==="
python3 tools/y2q_hxl1_extract_envdxe.py --out "$OUT"

if [[ ! -f "$REA" ]]; then
  echo "[STOP] Existing native REA fork missing: $REA" >&2
  exit 2
fi
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
node -e 'process.exit(process.platform==="linux" && Number(process.versions.node.split(".")[0])===24 ? 0 : 1)' || {
  echo "[STOP] Native Linux Node 24 required" >&2
  exit 2
}

if [[ -e "$EVIDENCE" ]]; then
  if python3 tools/y2q_hxl1_envdxe_rea_xrefs.py \
       --out "$OUT" --verify-only >/dev/null 2>&1; then
    echo "[REUSE] Verified original EnvDxe GUID xrefs Evidence"
  else
    echo "[STOP] Existing GUID xrefs Evidence failed provenance. Preserving $EVIDENCE" >&2
    echo "[DIAGNOSTICS] Inspect REA result; do not reuse a foreign PE's xrefs" >&2
    exit 2
  fi
else
  GUID_VA="$(python3 - "$OUT" <<'PY'
import sys
from pathlib import Path
from tools.y2q_hxl1_envdxe_rea_xrefs import source_info
print(source_info(Path(sys.argv[1]))["preferredAddress"])
PY
)"
  if [[ ! "$GUID_VA" =~ ^0x[[:xdigit:]]+$ ]]; then
    echo "[STOP] Original EnvDxe GUID has no trustworthy PE import coordinate" >&2
    exit 2
  fi
  echo "[GHIDRA] One exact original EnvDxe RAM GUID xrefs query at $GUID_VA"
  TMP="$OUT/rea-envdxe-ram-guid-xrefs.partial.json"
  if [[ -e "$TMP" ]]; then
    echo "[STOP] Previous partial REA evidence exists: $TMP" >&2
    exit 2
  fi
  if ! node "$REA" xrefs "$EFI" "$GUID_VA" --provider ghidra --json \
      > "$TMP" 2> "$OUT/rea-envdxe-ram-guid-xrefs-stderr.txt"; then
    echo "[STOP] Ghidra xrefs failed; inspect partial JSON and stderr" >&2
    exit 2
  fi
  mv "$TMP" "$EVIDENCE"
fi

python3 tools/y2q_hxl1_envdxe_rea_xrefs.py --out "$OUT"
cat "$OUT/rea-envdxe-ram-guid-xrefs-audit.md"
echo "[LIMIT] GUID references are not yet proof of InstallMultipleProtocolInterfaces"
