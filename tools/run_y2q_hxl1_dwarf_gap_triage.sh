#!/usr/bin/env bash
# HXL1 post-6,412-pass kernel investigation: explain absent rtmutex DWARF.
# Read-only retained .o, .cmd and stock source/kernel; NO new compilation,
# ADB, exploit, kernel pointer derivation, or source/build changes.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Selected regression: DWARF DIE, Kbuild flags and Stage-3 provenance ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_dwarf_gap_triage.py \
  tools/test_y2q_hxl1_kernel_proof_matrix.py \
  tools/test_y2q_dwarf_type_presence.py \
  tools/test_y2q_partial_samsung_dwarf_audit.py \
  tools/test_y2q_stage3_layout_inventory.py \
  tools/test_y2q_rtmutex_fix_audit.py \
  tools/test_y2q_porting_readiness.py

echo "=== Audit selected retained object debug types and original build flags ==="
python3 tools/y2q_hxl1_dwarf_gap_triage.py

echo "=== Exact HXL1 provisional DWARF blocker explanation ==="
cat "$HOME/s20-artifacts/hxl1-research/kernel-dwarf-gap-triage.md"
echo "[LIMIT] No factory ABI equivalence, type-member offsets, exploit, KernelSU or phone access"
