#!/usr/bin/env bash
# Experimental source-derived RT-mutex DWARF only, not OEM kernel ABI.
# Dry-run by default, pass --execute to opt in to a brand-new O= compilation.
# Uses a four-patch manifest-verified stock kernel source clone.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Isolated RT-mutex/futex Clang18 object compilation regressions ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_isolated_dwarf_objects.py \
  tools/test_prepare_samsung_vdso_compat.py \
  tools/test_build_samsung_stock_kernel.py

echo "=== Source/config provenance-gated targeted object build ==="
python3 tools/y2q_hxl1_isolated_dwarf_objects.py "$@"
echo "[LIMIT] Only a fresh experimental O= output; never OEM member offsets or a root payload"
