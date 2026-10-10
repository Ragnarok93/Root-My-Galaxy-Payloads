#!/usr/bin/env bash
# Original HXL1 XBL provider-side reconnaissance, exact protocol GUID only.
# Entirely host-side. No ADB, Ghidra imports, exploit, device or firmware writes.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Original HXL1 XBL exact EFI_RAMPARTITION GUID fixture tests ==="
python3 -m unittest -q tools/test_y2q_hxl1_xbl_ram_guid_locator.py

echo "=== SHA256-pinned XBL and XBL_CONFIG, narrow known EFI GUID lookup ==="
python3 tools/y2q_hxl1_xbl_ram_guid_locator.py

OUT="$HOME/s20-artifacts/hxl1-research/xbl-rampartition/original-xbl-rampartition-guid.md"
cat "$OUT"
echo "[LIMIT] A literal firmware GUID is not proof of protocol registration or runtime BaseMemory."
