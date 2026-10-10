#!/usr/bin/env bash
# Original HXL1 EnvDxe: corrected callback ownership, 8 code windows, 4 xrefs.
# 659 independent offline tests: previously authenticated 325 + new 334.
# SHA-pinned PE only. NEVER connects to or modifies S20+, bootloader, kernel.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== 659 meaningful original XBL EnvDxe regression tests ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_envdxe_ram_registration_interface.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_callback.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_parent_chain.py \
  tools/test_y2q_hxl1_envdxe_callback_raw_proof.py \
  tools/test_y2q_hxl1_envdxe_callback_mutations.py \
  tools/test_y2q_hxl1_envdxe_method_arm64_trace.py \
  tools/test_y2q_hxl1_envdxe_helper_batch.py

echo "=== Original PE and verified callback/callee method ownership ==="
[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Original stock SHA-pinned EnvDxe or REA missing" >&2
  exit 2
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original SHA256 mismatch" >&2; exit 2
}
python3 - "$OUT" <<'PY'
from pathlib import Path
import sys
from tools.y2q_hxl1_envdxe_helper_batch import original_parent
from tools.y2q_hxl1_envdxe_method_arm64_trace import original_window
folder=Path(sys.argv[1])
parent=original_parent(folder)
print("[VERIFIED] GetRamPartitions 0x1f74 -> 0x52cc")
print("[VERIFIED] Method 0x1f28 -> 0x5740; 0x1ff0 is post-callback")
for addr,size in (
    ("0x52cc",224),("0x3c3c",128),("0x5740",128),("0x2618",128),
    ("0x5388",40),("0x5398",24),("0x1fe8",96),("0x81f4",128)
):
    src=original_window(folder,addr,size)
    print("[ORIGINAL PE EXECUTABLE]",addr,size,src["sectionName"],src["sha256"])
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
  echo "[STOP] Native Linux Node24 required" >&2; exit 2
}

echo "=== Eight exact read-only Ghidra code windows; preserve partials ==="
while IFS='|' read -r label address size; do
  output="$OUT/rea-envdxe-helper-window-$label.json"
  if python3 tools/y2q_hxl1_envdxe_helper_batch.py \
      --out "$OUT" --verify "$label" --kind window >/dev/null 2>&1; then
    echo "[REUSE] Original byte-provenance $label"
    continue
  fi
  [[ ! -e "$output" && ! -L "$output" ]] || {
    echo "[STOP] Conflicting saved Ghidra helper code: $output" >&2
    exit 2
  }
  partial="$OUT/rea-envdxe-helper-window-$label.partial.json"
  if [[ -e "$partial" || -L "$partial" ]]; then
    echo "[LIMIT] Existing failed Ghidra read preserved: $partial"
    continue
  fi
  echo "[GHIDRA READ] $label $address ($size bytes)"
  if node "$REA" read-bytes "$EFI" "$address" --length "$size" \
      --provider ghidra --json > "$partial" \
      2> "$OUT/rea-envdxe-helper-window-$label-stderr.txt"; then
    mv "$partial" "$output"
    python3 tools/y2q_hxl1_envdxe_helper_batch.py \
      --out "$OUT" --verify "$label" --kind window
  else
    echo "[LIMIT] Optional imported Ghidra helper read unavailable: $label"
  fi
done <<'WINDOWS'
ram-helper-tail|0x52cc|224
ram-helper-copy-callee|0x3c3c|128
other-method-callee|0x5740|128
post-callback-callee|0x2618|128
ram-helper-branch-5388|0x5388|40
ram-helper-branch-5398|0x5398|24
post-callback-code|0x1fe8|96
additional-smem-caller|0x81f4|128
WINDOWS

echo "=== Four exact Ghidra xrefs to distinct code paths ==="
while IFS='|' read -r label address; do
  output="$OUT/rea-envdxe-helper-xrefs-$label.json"
  if python3 tools/y2q_hxl1_envdxe_helper_batch.py \
      --out "$OUT" --verify "$label" --kind xrefs >/dev/null 2>&1; then
    echo "[REUSE] Verified original xrefs $label"
    continue
  fi
  [[ ! -e "$output" && ! -L "$output" ]] || {
    echo "[STOP] Conflicting original helper references: $output" >&2
    exit 2
  }
  partial="$OUT/rea-envdxe-helper-xrefs-$label.partial.json"
  if [[ -e "$partial" || -L "$partial" ]]; then
    echo "[LIMIT] Previous failed xref query preserved: $partial"
    continue
  fi
  echo "[GHIDRA XREFS] $label $address"
  if node "$REA" xrefs "$EFI" "$address" --provider ghidra --json \
      > "$partial" 2> "$OUT/rea-envdxe-helper-xrefs-$label-stderr.txt"; then
    mv "$partial" "$output"
    python3 tools/y2q_hxl1_envdxe_helper_batch.py \
      --out "$OUT" --verify "$label" --kind xrefs
  else
    echo "[LIMIT] Optional imported Ghidra references unavailable: $label"
  fi
done <<'XREFS'
ram-helper-copy-callee|0x3c3c
other-method-callee|0x5740
post-callback-callee|0x2618
post-callback-code|0x1fe8
XREFS

echo "=== Aggregate original ARM64 helper and corrected method ownership ==="
python3 tools/y2q_hxl1_envdxe_helper_batch.py --out "$OUT"
cat "$OUT/rea-envdxe-helper-batch.md"
echo "[LIMIT] Static XBL proof only; no live DRAM BaseMemory, GhostLock, root or KernelSU"
