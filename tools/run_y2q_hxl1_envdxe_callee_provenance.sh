#!/usr/bin/env bash
# S20+ stock HXL1 XBL: 3 distinct existing ARM64 callback/helper leads.
# 1389 verified prior tests + 1552 novel callee provenance checks = 2941.
# Five minutes of repeated scanning is avoided: reuse all prior Ghidra data,
# collect only 3 x code windows and 3 xrefs, then assemble one report.
# Original stock PE only, no phone interaction, bootloader or exploit.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== 2941 HXL1 EnvDxe offline callback/callee provenance tests ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_envdxe_ram_registration_interface.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_callback.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_parent_chain.py \
  tools/test_y2q_hxl1_envdxe_callback_raw_proof.py \
  tools/test_y2q_hxl1_envdxe_callback_mutations.py \
  tools/test_y2q_hxl1_envdxe_method_arm64_trace.py \
  tools/test_y2q_hxl1_envdxe_helper_batch.py \
  tools/test_y2q_hxl1_envdxe_callback_cfg.py \
  tools/test_y2q_hxl1_envdxe_callee_provenance.py

[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Pinned stock EnvDxe or REA scripts not available" >&2; exit 2
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original stock HXL1 EnvDxe hash mismatch" >&2; exit 2
}
echo "=== Authenticate complete callback CFG and prior original Ghidra evidence ==="
python3 - "$OUT" <<'PY'
from pathlib import Path
import sys
from tools.y2q_hxl1_envdxe_callee_provenance import previous
from tools.y2q_hxl1_envdxe_method_arm64_trace import original_window
folder=Path(sys.argv[1])
callback,old=previous(folder)
for r in callback["cfg"]["reachableCalls"]:
    print("[AUTHENTIC ORIGINAL CALLBACK]",r["pc"],"calls",r["target"])
for at,size in (("0x26bc",192),("0x25d8",160),("0x3d04",160)):
    code=original_window(folder,at,size)
    print("[AUTHENTIC ORIGINAL EXECUTABLE]",at,code["sectionName"],code["sha256"])
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
  echo "[STOP] Host REA must use native Linux Node.js 24" >&2; exit 2
}

echo "=== Three independent original Ghidra code reads; reuse exact results ==="
while IFS='|' read -r label addr size; do
  FILE="$OUT/rea-envdxe-callee-provenance-bytes-$label.json"
  if python3 tools/y2q_hxl1_envdxe_callee_provenance.py \
       --out "$OUT" --verify "$label" --kind bytes >/dev/null 2>&1; then
    echo "[REUSE] Verified original callee bytes $label"
    continue
  fi
  [[ ! -e "$FILE" && ! -L "$FILE" ]] || {
    echo "[STOP] Saved source/Ghidra evidence conflicts: $FILE" >&2; exit 2
  }
  PARTIAL="$OUT/rea-envdxe-callee-provenance-bytes-$label.partial.json"
  [[ ! -e "$PARTIAL" && ! -L "$PARTIAL" ]] || {
    echo "[STOP] Previous partial preserved; inspect $PARTIAL" >&2; exit 2
  }
  echo "[GHIDRA CODE] $label $addr $size bytes"
  if node "$REA" read-bytes "$EFI" "$addr" --length "$size" \
       --provider ghidra --json > "$PARTIAL" \
       2> "$OUT/rea-envdxe-callee-provenance-bytes-$label-stderr.txt"; then
    mv "$PARTIAL" "$FILE"
    python3 tools/y2q_hxl1_envdxe_callee_provenance.py \
      --out "$OUT" --verify "$label" --kind bytes
  else
    echo "[STOP] Ghidra read failed, partial retained: $PARTIAL" >&2; exit 2
  fi
done <<'WINDOWS'
callback-tail-callee|0x26bc|192
secondary-ram-helper|0x25d8|160
record-copy-subroutine|0x3d04|160
WINDOWS

echo "=== Three exact helper xref sets, including known callers ==="
while IFS='|' read -r label addr; do
  FILE="$OUT/rea-envdxe-callee-provenance-refs-$label.json"
  if python3 tools/y2q_hxl1_envdxe_callee_provenance.py \
       --out "$OUT" --verify "$label" --kind xrefs >/dev/null 2>&1; then
    echo "[REUSE] Verified original callee xrefs $label"
    continue
  fi
  [[ ! -e "$FILE" && ! -L "$FILE" ]] || {
    echo "[STOP] Saved original callee xrefs conflict: $FILE" >&2; exit 2
  }
  PARTIAL="$OUT/rea-envdxe-callee-provenance-refs-$label.partial.json"
  [[ ! -e "$PARTIAL" && ! -L "$PARTIAL" ]] || {
    echo "[STOP] Previous xref partial preserved: $PARTIAL" >&2; exit 2
  }
  echo "[GHIDRA XREFS] $label $addr"
  if node "$REA" xrefs "$EFI" "$addr" --provider ghidra --json > "$PARTIAL" \
       2> "$OUT/rea-envdxe-callee-provenance-refs-$label-stderr.txt"; then
    mv "$PARTIAL" "$FILE"
    python3 tools/y2q_hxl1_envdxe_callee_provenance.py \
       --out "$OUT" --verify "$label" --kind xrefs
  else
    echo "[STOP] Ghidra xref failed, partial retained: $PARTIAL" >&2; exit 2
  fi
done <<'XREFS'
callback-tail-callee|0x26bc
secondary-ram-helper|0x25d8
record-copy-subroutine|0x3d04
XREFS

echo "=== Final original firmware callee/callback provenance report ==="
python3 tools/y2q_hxl1_envdxe_callee_provenance.py --out "$OUT"
cat "$OUT/rea-envdxe-callee-provenance.md"
echo "[LIMIT] Static original HXL1 evidence only; no live RAM/kernel/root"
