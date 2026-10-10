#!/usr/bin/env bash
# One narrow original HXL1 EnvDxe REA/Ghidra function pass.
# Source instructions and target addresses arise from verified 14:32 UTC output.
# Host-only, read-only PE analysis: no ADB, rooting, flashing or device writes.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== Offline EnvDxe proof-gate regression tests ==="
python3 -m unittest -q tools/test_y2q_hxl1_envdxe_provider_followup.py

echo "=== Authenticate original EnvDxe and exact RAM-table string/callsite evidence ==="
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Expected original EnvDxe PE or local REA fork missing" >&2
  exit 2
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original stock EnvDxe SHA256 mismatch" >&2
  exit 2
}
python3 - "$OUT" <<'PY'
import sys
from pathlib import Path
from tools.y2q_hxl1_envdxe_provider_followup import authenticate_parent
p=authenticate_parent(Path(sys.argv[1]))
print("[VERIFIED] Init 0x1150 calls thunk_FUN_000022b0")
for r in p["diagnostics"]:
    if r["label"] in ("ram-table-lib","ram-entry-limit"):
        print("[VERIFIED RAM SOURCE XREFS]",r["label"],
              ",".join(r["referenceInstructionAddresses"]))
PY

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
  echo "[STOP] Native Linux Node 24 required" >&2
  exit 2
}

echo "=== Original EnvDxe: one initialization thunk and two RAM-source functions ==="
while IFS='|' read -r label address; do
  file="$OUT/rea-envdxe-followup-$label.json"
  if python3 tools/y2q_hxl1_envdxe_provider_followup.py \
       --out "$OUT" --verify-single "$label" >/dev/null 2>&1; then
    echo "[REUSE] Authenticated original Ghidra function $label"
    continue
  fi
  [[ ! -e "$file" ]] || {
    echo "[STOP] Existing untrusted Ghidra function evidence: $file" >&2
    exit 2
  }
  partial="$OUT/rea-envdxe-followup-$label.partial.json"
  [[ ! -e "$partial" ]] || {
    echo "[STOP] Previous partial REA output requires inspection: $partial" >&2
    exit 2
  }
  echo "[GHIDRA FUNCTION] $label at original static coordinate $address"
  if ! node "$REA" function "$EFI" "$address" --provider ghidra --json \
       > "$partial" 2> "$OUT/rea-envdxe-followup-$label-stderr.txt"; then
    echo "[STOP] REA/Ghidra failed for $label; inspect partial and stderr" >&2
    exit 2
  fi
  mv "$partial" "$file"
  python3 tools/y2q_hxl1_envdxe_provider_followup.py \
       --out "$OUT" --verify-single "$label"
done <<'FUNCTIONS'
initializer-dispatch|0x22b0
ram-table-region-a|0x554c
ram-table-region-b|0x572c
FUNCTIONS

python3 tools/y2q_hxl1_envdxe_provider_followup.py --out "$OUT"
cat "$OUT/rea-envdxe-provider-followup.md"
echo "[LIMIT] No live BaseMemory/kernel load, protocol installer or KernelSU proven"
