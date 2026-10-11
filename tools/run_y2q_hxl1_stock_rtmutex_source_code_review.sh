#!/usr/bin/env bash
# Strictly read-only original HXL1 code/source review. Original source and
# original kernel Image are rehashed; v2 reported disassembly is independently
# checked word-by-word. No new build, device operation or root method.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Source/stock ARM64 dataflow-review provenance regressions ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_stock_rtmutex_source_code_review.py \
  tools/test_y2q_hxl1_stock_rtmutex_code_windows.py \
  tools/test_y2q_rtmutex_fix_audit.py

echo "=== Original Samsung C functions and authenticated stock disassembly ==="
python3 tools/y2q_hxl1_stock_rtmutex_source_code_review.py \
  --show-review "$@"
echo "[LIMIT] Source/function-name pairing, NOT proven factory member geometry, exploit or KernelSU"
