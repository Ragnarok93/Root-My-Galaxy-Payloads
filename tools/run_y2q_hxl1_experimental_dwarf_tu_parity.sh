#!/usr/bin/env bash
# Host only: independently compare Clang18 direct-member DWARF geometry across
# original signed-off rtmutex.o and futex.o, with NO factory-ABI promotion.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Read-only exact HXL1 experimental translation-unit parity regressions ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_experimental_dwarf_tu_parity.py \
  tools/test_y2q_hxl1_attest_isolated_dwarf_objects.py
echo "=== Reconfirm original object identity and compare direct-member fingerprints ==="
python3 tools/y2q_hxl1_experimental_dwarf_tu_parity.py "$@"
echo "[LIMIT] Only two experimental Clang18 units, NOT OEM factory layouts, root or KernelSU"
