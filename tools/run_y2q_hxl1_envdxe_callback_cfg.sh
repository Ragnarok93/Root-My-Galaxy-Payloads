#!/usr/bin/env bash
# Original S20+ HXL1 EnvDxe: repair incorrect end-of-callback assumption.
# 659 previously authenticated tests + 729 new, distinct source/bit-level
# regressions. ONE new 20-byte Ghidra read; reuse original 128+96 bytes.
# NO phone access, privileged commands, memory dumps or firmware writes.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== 1388 host-only original EnvDxe provenance and callback-CFG tests ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_envdxe_ram_registration_interface.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_callback.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_parent_chain.py \
  tools/test_y2q_hxl1_envdxe_callback_raw_proof.py \
  tools/test_y2q_hxl1_envdxe_callback_mutations.py \
  tools/test_y2q_hxl1_envdxe_method_arm64_trace.py \
  tools/test_y2q_hxl1_envdxe_helper_batch.py \
  tools/test_y2q_hxl1_envdxe_callback_cfg.py

[[ -f "$EFI" && ! -L "$EFI" && -f "$REA" ]] || {
  echo "[STOP] Missing pinned HXL1 original EnvDxe or REA scripts" >&2
  exit 2
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Original firmware PE digest mismatch" >&2
  exit 2
}

# The old 128-byte callback entry and 96-byte 'post-callback' snippet already
# cover [0x1f74,0x2048) with a 12-byte overlap. This collects exactly the
# uncovered bytes [0x2048,0x205c), NOTHING else.
FILE="$OUT/rea-envdxe-callback-cfg-tail-2048.json"
if [[ -e "$FILE" || -L "$FILE" ]]; then
  echo "[REUSE] Checking previously imported final 20 bytes"
  python3 tools/y2q_hxl1_envdxe_callback_cfg.py --out "$OUT" --verify-tail
else
  PARTIAL="$OUT/rea-envdxe-callback-cfg-tail-2048.partial.json"
  [[ ! -e "$PARTIAL" && ! -L "$PARTIAL" ]] || {
    echo "[STOP] Previous REA failure retained at $PARTIAL; inspect before retry" >&2
    exit 2
  }
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
    echo "[STOP] REA requires native Linux Node.js 24" >&2
    exit 2
  }
  echo "=== Single new REA/Ghidra original read: 0x2048 size 20 ==="
  if node "$REA" read-bytes "$EFI" 0x2048 --length 20 --provider ghidra --json \
      > "$PARTIAL" 2> "$OUT/rea-envdxe-callback-cfg-tail-2048-stderr.txt"; then
    mv "$PARTIAL" "$FILE"
    python3 tools/y2q_hxl1_envdxe_callback_cfg.py --out "$OUT" --verify-tail
  else
    echo "[STOP] Ghidra final 20-byte read failed; partial retained at $PARTIAL" >&2
    exit 2
  fi
fi

echo "=== Assemble 3 nonredundant readbacks and reconstruct static reachability ==="
python3 tools/y2q_hxl1_envdxe_callback_cfg.py --out "$OUT"
cat "$OUT/rea-envdxe-getram-full-cfg.md"
echo "[LIMIT] No live RAM partitions, physical kernel address, root or KernelSU"
