#!/usr/bin/env bash
# Authenticated stock HXL1 EnvDxe memory lifetime, with no new Ghidra scan.
# 2941 previously completed tests plus 3471 semantic/negative checks = 6412.
# No device, root, raw runtime RAM or firmware writes.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition"
EFI="$OUT/EnvDxe-HXL1.efi"
PIN=9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670

echo "=== 6412 HXL1 EnvDxe original ABI/ownership tests ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_envdxe_ram_registration_interface.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_callback.py \
  tools/test_y2q_hxl1_envdxe_ram_registration_parent_chain.py \
  tools/test_y2q_hxl1_envdxe_callback_raw_proof.py \
  tools/test_y2q_hxl1_envdxe_callback_mutations.py \
  tools/test_y2q_hxl1_envdxe_method_arm64_trace.py \
  tools/test_y2q_hxl1_envdxe_helper_batch.py \
  tools/test_y2q_hxl1_envdxe_callback_cfg.py \
  tools/test_y2q_hxl1_envdxe_callee_provenance.py \
  tools/test_y2q_hxl1_envdxe_efi_pool_ownership.py

[[ -f "$EFI" && ! -L "$EFI" ]] || {
  echo "[STOP] Missing original stock EnvDxe PE" >&2
  exit 2
}
echo "$PIN  $EFI" | sha256sum -c --status || {
  echo "[STOP] Stock original EnvDxe SHA256 mismatch" >&2
  exit 2
}

echo "=== Reuse original PE, callback CFG and all three original Ghidra readbacks ==="
python3 tools/y2q_hxl1_envdxe_efi_pool_ownership.py --out "$OUT"
cat "$OUT/rea-envdxe-efi-pool-ownership.md"
echo "[LIMIT] Static EFI Boot Services ABI; no device root/runtime RAM or kernel load proven"
