#!/usr/bin/env bash
# HXL1 Stage-3 missing rtmutex.o/futex.o: read-only stock Kbuild & historical logs.
# No make invocation, code compilation, device writes, root, or offset derivation.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Original kernel ABI/DWARF and missing-object build evidence regressions ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_target_build_blockers.py \
  tools/test_y2q_hxl1_dwarf_gap_triage.py \
  tools/test_y2q_hxl1_kernel_proof_matrix.py \
  tools/test_y2q_dwarf_type_presence.py \
  tools/test_y2q_partial_samsung_dwarf_audit.py \
  tools/test_y2q_stage3_layout_inventory.py \
  tools/test_y2q_rtmutex_fix_audit.py \
  tools/test_y2q_porting_readiness.py

echo "=== Reconcile two absent objects with Kbuild rules and historical error lines ==="
python3 tools/y2q_hxl1_target_build_blockers.py "$@"

echo "=== HXL1 target-object blocker matrix ==="
cat "$HOME/s20-artifacts/hxl1-research/kernel-target-build-blockers.md"
echo "[LIMIT] No compile performed; historical errors are not factory ABI or rooting proof"
