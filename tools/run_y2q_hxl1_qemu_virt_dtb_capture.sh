#!/usr/bin/env bash
# Produce only a QEMU virt machine DTB; do NOT execute guest instructions.
set -euo pipefail
readonly KERNEL_SHA=ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
KERNEL="$HOME/s20-artifacts/kernel.bin"
OUTPUT="$HOME/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011"
if (( $# > 0 )); then OUTPUT="$1"; fi
fail() { printf '[STOP] %s\n' "$*" >&2; exit 2; }

[[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] ||
  fail "Output already exists; pass a fresh output directory"
[[ -f "$KERNEL" && ! -L "$KERNEL" ]] || fail "Original kernel missing or symlink"
command -v sha256sum >/dev/null || fail "sha256sum unavailable"
printf '%s  %s\n' "$KERNEL_SHA" "$KERNEL" | sha256sum -c --status ||
  fail "Original HXL1 Image SHA mismatch"
command -v qemu-system-aarch64 >/dev/null || fail "qemu-system-aarch64 unavailable"
command -v timeout >/dev/null || fail "GNU timeout unavailable"
# The actual QEMU machine used in the successful SMC breakpoint session was:
# virt,gic-version=3 / cortex-a57 / 1 CPU / 2048 MiB RAM.
mkdir -p -- "$OUTPUT"
printf '%s\n' 'virt,gic-version=3; cortex-a57; 1 CPU; 2048 MiB' \
  > "$OUTPUT/machine-profile.txt"
qemu-system-aarch64 --version > "$OUTPUT/qemu-version.txt"
set +e
# -S is a defense-in-depth halt even if a particular QEMU does not exit
# immediately after dumping its generated device tree.
timeout --signal=TERM --kill-after=2s 12s \
  qemu-system-aarch64 \
    -machine "virt,gic-version=3,dumpdtb=$OUTPUT/qemu-virt.dtb" \
    -cpu cortex-a57 -smp 1 -m 2048 \
    -kernel "$KERNEL" -S \
    -display none -serial none -monitor none -no-reboot -nic none \
    > "$OUTPUT/qemu-dtb-stdout.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$OUTPUT/qemu-dtb-exit-status.txt"
if [[ "$status" -ne 0 || ! -s "$OUTPUT/qemu-virt.dtb" ]]; then
  printf '[INCONCLUSIVE] DTB dump did not succeed (QEMU exit=%s)\n' "$status"
  echo "[LOG] $OUTPUT/qemu-dtb-stdout.log"
  exit 3
fi
echo "[DTB] $OUTPUT/qemu-virt.dtb"
echo "[LIMIT] -S and dumpdtb; no guest execution, RKP handler or reserved pool"
