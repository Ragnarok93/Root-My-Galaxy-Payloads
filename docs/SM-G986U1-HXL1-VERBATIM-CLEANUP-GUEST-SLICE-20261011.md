# HXL1 — original Samsung `remove_waiter()` source fragment execution

**Target:** SM-G986U1 / G986U1UESCHXL1, Android shipping kernel `4.19.113-27095354`.

## Milestone

The previously owner-executed deterministic ownership model proved the *modeled* state transition only. The next committed tool, `tools/y2q_hxl1_original_cleanup_slice.py`, extracts and **compiles the untouched function-definition text** of `static void remove_waiter(...)` from the owner's exact original Samsung `kernel/locking/rtmutex.c`, requiring SHA-256 `36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9`.

The tool builds a temporary, unprivileged C program with *inert mocked* RT-mutex helpers, then calls the extracted function with a deliberately `NULL` mutex owner. This avoids owner-chain traversal and all actual kernel locking. It tests cases `current == waiter->task` and `current != waiter->task`. With the observed shipping source semantics the current task's `pi_blocked_on` is cleared in both cases, but the distinct waiter task's is not. The function text itself is not edited or reimplemented in the harness; **the dependency behavior is mocked**.

If the host has `aarch64-linux-gnu-gcc` and `qemu-aarch64`, the exact same source is **additionally** cross-compiled as static AArch64 Linux user-space code and executed by QEMU **user-mode** emulation. This is **not** an ARM64 Linux kernel boot. The complete original Samsung compiled function from `kernel.bin` is **not** executed; the source fragment is recompiled in a different harness with synthetic task structs. No original OEM alignment/ABI equivalence is implied by passing the harness.

## Run once on owner WSL (after GitHub pull)

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_original_cleanup_slice
python3 tools/y2q_hxl1_original_cleanup_slice.py
```

A successful run writes the **new**, non-overwriting report `~/s20-artifacts/hxl1-research/original-source-fragment-regression.json`. When both ARM64 user-mode tools are present, `arm64UserMode.architecture` is `aarch64-user` and two observations are compared with the native run. Otherwise it reports `arm64UserMode.status=UNAVAILABLE`, not a fictitious emulated kernel PASS. To **require** ARM64 user emulation, add `--require-arm64` and install the cross-compiler and `qemu-user` packages if missing.

**Locally verified before committing:** Five focused tests pass on a representative Linux 4.19-shaped source fixture, including actual host C compilation/execution and rejection of incorrect SHA, patched cleanup semantics, absent function and malformed body. The GitHub CI workflow runs this test module in addition to the existing isolated model. The assistant does **not** possess the owner's original Samsung source tree; exact HXL1 compilation has to be executed once on their WSL. If their HXL1 source has additional fields/callees not represented in the small stub layer, the tool fails with compiler diagnostics; do not report a PASS until it succeeds.

## Hard evidence boundary

- **New:** actual untouched, SHA-256-verified OEM *C function text* executed with inert dependencies in a disposable host process (and optionally emulated ARM64 user-mode process).
- **Still unproven:** Samsung-built ARM64 `remove_waiter` bytes executed, real kernel RT-mutex behavior, real device futex-PI reachability, source-exact Linux guest, memory corruption, kernel exploitability, bootloader unlock, root, KernelSU.
- The original `kernel.bin` and the user's phone are not read or modified by this action. No `futex()` kernel calls or crash-based tests are run.
- A source-faithful **whole-kernel** QEMU guest remains blocked by porting Samsung Qualcomm SoC dependencies to the generic `virt` platform and producing a working bootable Samsung kernel. The existing bootable upstream Linux 4.19.325 guest does not address this.

The readiness checker must not promote Stage 3 or Stage 7–8 on a harness-only result.
