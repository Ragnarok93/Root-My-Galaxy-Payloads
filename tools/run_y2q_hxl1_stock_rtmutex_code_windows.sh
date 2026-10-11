#!/usr/bin/env bash
# HXL1 stock Linux Image instruction windows; original code not Clang18 DWARF.
# No compile, root, live kernel access, CVE execution or phone contact.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Original stock Image and recovered-kallsyms trust-boundary tests ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_stock_rtmutex_code_windows.py \
  tools/test_y2q_hxl1_experimental_dwarf_tu_parity.py \
  tools/test_y2q_stage3_layout_inventory.py
echo "=== Independent SHA256-pinned stock ARM64 code windows ==="
python3 tools/y2q_hxl1_stock_rtmutex_code_windows.py "$@"
echo "[LIMIT] Static original code windows, recovered symbol names; no factory offsets or root"
