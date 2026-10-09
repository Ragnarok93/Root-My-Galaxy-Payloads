#!/usr/bin/env bash
# Read-only device-identity diagnostic; this is not a root payload.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NDK="${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an extracted Linux Android NDK}"
CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
if [[ ! -x "$CLANG" ]]; then
  echo "Expected Android ARM64 compiler not found: $CLANG" >&2
  exit 2
fi
mkdir -p "$ROOT/build"
"$CLANG" -O2 -g0 -Wall -Wextra -Werror -fPIE -pie \
  "$ROOT/identity_probe.c" -o "$ROOT/build/y2q-identity-probe"
file "$ROOT/build/y2q-identity-probe"
sha256sum "$ROOT/build/y2q-identity-probe"
echo "Built read-only diagnostic binary, NOT a root/KernelSU payload."
