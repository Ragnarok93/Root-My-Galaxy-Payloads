#!/usr/bin/env bash
# HXL1 off-device, exact stable 6f5459da ARM64 Clang IAS compatibility copy.
# Default is DRY RUN. --execute creates a NEW isolated copy only.
# Never edits the pinned Samsung stock source, older compatibility copies,
# retained Clang18 O= build, kernel image, phone, or bootloader.
set -euo pipefail
cd "$(dirname "$0")/.."

STOCK="$HOME/src/samsung-y2q-hxl1-stock"
NEW="$HOME/src/samsung-y2q-hxl1-vdso-ias-extable-compat"
AUDIT="$HOME/s20-artifacts/samsung-hxl1-source-audit.json"

echo "=== Exact upstream user_alt Clang IAS patch unit and provenance tests ==="
python3 -m unittest -q \
  tools/test_prepare_samsung_vdso_compat.py \
  tools/test_build_samsung_stock_kernel.py

echo "=== Verify unmodified 11-layer stock Samsung source, plan four-patch clone ==="
python3 tools/prepare_samsung_vdso_compat.py \
  --source-dir "$STOCK" \
  --compat-source-dir "$NEW" \
  --audit-json "$AUDIT" \
  --init-format-fix \
  --arm64-extable-ias-fix "$@"

echo "[LIMIT] No make/compile, target ELF, ROM install, physical addresses, exploit or KernelSU"
