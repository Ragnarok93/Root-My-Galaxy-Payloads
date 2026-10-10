#!/usr/bin/env bash
# XBL EnvDxe: FV/FFS/LZMA and verified gzip-only next step after 0 raw GUIDs.
# Read-only SHA256-pinned stock XBLs; no ADB or firmware extraction to files.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Original HXL1 XBL firmware-volume provider fixture tests ==="
python3 -m unittest -q \
  tools/test_y2q_hxl1_xbl_envdxe_fv_probe.py

echo "=== Only original XBLs; targeted EnvDxe/RAM protocol candidates ==="
python3 tools/y2q_hxl1_xbl_envdxe_fv_probe.py

cat "$HOME/s20-artifacts/hxl1-research/xbl-rampartition/original-xbl-envdxe-fv.md"
echo "[LIMIT] XBL DXE module candidates are not boot-time RAM partition measurements."
