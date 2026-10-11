#!/usr/bin/env bash
# Exact owner successful Clang18-targeted RT-mutex/futex compilation post-audit.
# Read-only; does NOT run make or modify source/objects or communicate with S20+.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Provenance regression: original successful 2-object Clang18 build ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_attest_isolated_dwarf_objects.py \
  tools/test_y2q_hxl1_isolated_dwarf_objects.py \
  tools/test_y2q_hxl1_dwarf_gap_triage.py
echo "=== Verify stock SHA, compatibility clone, actual object hashes and 2x2 type definitions ==="
python3 tools/y2q_hxl1_attest_isolated_dwarf_objects.py "$@"
echo "[LIMIT] Experimental Clang18 ABI only; no OEM offsets, boot/kernel load, exploit or KernelSU"
