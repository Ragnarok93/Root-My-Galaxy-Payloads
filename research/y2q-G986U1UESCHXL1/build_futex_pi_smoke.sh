#!/usr/bin/env bash
# Offline Android ARM64 build of the benign HXL1 futex-PI smoke test.
# Produces an ordinary user-space executable, NOT a root/kernel payload.
set -euo pipefail
ROOT="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
NDK="\${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the installed Android NDK}"
CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
if [[ ! -x "$CLANG" ]]; then
  echo "Missing Android ARM64 compiler: $CLANG" >&2
  exit 2
fi
mkdir -p "$ROOT/build"
OUT="$ROOT/build/y2q-HXL1-futex-pi-smoke"
"$CLANG" -std=c11 -O2 -g0 -Wall -Wextra -Werror \
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -fPIE -pie -Wl,--no-undefined \
  "$ROOT/futex_pi_smoke.c" -o "$OUT"
file "$OUT"
sha256sum "$OUT"
echo "Built benign ARM64 user-space futex-PI smoke executable (NOT ROOT)."
