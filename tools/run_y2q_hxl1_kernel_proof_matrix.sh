#!/usr/bin/env bash
# Exact Samsung SM-G986U1 HXL1, Stage 3 ABI/source-provenance reconciliation.
# 5 independent existing auditors, one explicit decision report; no ADB.
# No exploit, kernel-code execution, bootloader change, or signed-module bypass.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="$HOME/s20-artifacts/hxl1-research/kernel-proof-matrix.json"
ORIGINAL="$HOME/src/samsung-y2q-hxl1-stock"
BUILD="$HOME/src/samsung-y2q-hxl1-config-clang18"
ARTIFACTS="$HOME/s20-artifacts"
REFERENCES="$HOME/s20-artifacts/hxl1-research/rtmutex-fix-review"

echo "=== Regression contracts: kernel provenance, source fixes, and readiness ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_kernel_proof_matrix.py \
  tools/test_y2q_stage3_layout_inventory.py \
  tools/test_y2q_partial_samsung_dwarf_audit.py \
  tools/test_y2q_dwarf_type_presence.py \
  tools/test_y2q_rtmutex_fix_audit.py \
  tools/test_y2q_porting_readiness.py

echo "=== Five original/experimental provenance audits in one host-only pass ==="
python3 tools/y2q_hxl1_kernel_proof_matrix.py \
  --source "$ORIGINAL" \
  --build "$BUILD" \
  --artifacts "$ARTIFACTS" \
  --references "$REFERENCES" \
  --output "$OUT"

cat "$HOME/s20-artifacts/hxl1-research/kernel-proof-matrix.md"
echo "[LIMIT] Source/Clang18 DWARF availability only; not OEM kernel field offsets, live kernel load or root"
