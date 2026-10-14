# SM-G986U1 HXL1 — factory source / ARM64 disassembly crosswalk

Date: 2026-10-14 UTC. Research scope: original Samsung source supplied by the device owner, plus previously verified original-image-derived static disassembly. **Offline-only; no bootloader changes, ADB, kernel access, exploit or KernelSU.**

## Inputs and provenance

The owner uploaded `hxl1-source-dispatch-review.tar.gz` with exactly `kernel/futex.c` and `fs/select.c`:

| File | SHA-256 | Provenance |
|---|---|---|
| `kernel/futex.c` | `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5` | Matches the previously pinned HXL1 Samsung source hash |
| `fs/select.c` | `8b73f69f3f1929a39d7d7549f96cf6fa670420e140b9d67cae8177d1fe4642f3` | SHA newly calculated from the submitted file; **no independent prior factory hash comparison** |

The existing `hxl1-disassembly-review.tar.gz` has five next-symbol-bounded ARM64 function windows, **5/5 disassembly text hashes matching `stack-gate.json`** and **4,102 contiguous 32-bit instruction slots**. The archive lacks original raw `kernel.bin`, so the original-image hash remains an assertion from the earlier owner-side pinned extractor, not a new independent byte-for-byte confirmation.

## Source-to-compiled code correspondence

| Exact Samsung source | Observed archived native code | Confidence |
|---|---|---|
| `kernel/futex.c:3687-3744`: `do_futex` command switch handles `FUTEX_WAIT_REQUEUE_PI` (11) by calling `futex_wait_requeue_pi` | `do_futex` compares command with 11 and takes a branch **within the same bounded code window** | Direct dispatch equivalence |
| `kernel/futex.c:3232-3251`: the `static int futex_wait_requeue_pi` implementation rejects identical `uaddr` and `uaddr2` | Its opcode-11 region compares the registers saved from original input arguments and branches on equality | Strong instruction/source guard correspondence |
| `kernel/futex.c:3739-3741`: `FUTEX_CMP_REQUEUE_PI` (12) invokes `futex_requeue` | Opcode 12 leads to a branch-with-link targeting the extracted `futex_requeue` function | Direct call-target verification |
| `fs/select.c:594-650`: `core_sys_select` uses an on-stack `stack_fds` array, with `kvmalloc` fallback for larger arguments | `core_sys_select` forms an SP-relative buffer address and has a size-dependent branch into a different allocation path | Strong source/control-flow correspondence; no source C-local size certification |
| `fs/select.c:650`: `core_sys_select` calls `do_select` | Direct call resolves to the previously extracted original `do_select` code window | Direct call-target verification |

The original `futex_wait_requeue_pi` source further declares `struct rt_mutex_waiter rt_waiter` (line 3238), `struct futex_q q` (line 3241), and uses `futex_wait_queue_me` and `rt_mutex_wait_proxy_lock`. There are compatible internal initialization and call sequences within the compiled operation-11 region, but exact source-to-address attribution for the waiter, queue and their lifetimes has **not** been independently authenticated.

**Interpretation:** The large in-window body for opcode 11, combined with the verified source helper call and its equal-address guard, **strongly supports compiler expansion / inlining into `do_futex`**. It is not a proof of every compiler optimization, all original C locals, or complete OEM DWARF member placement. Missing recovered `futex_wait_requeue_pi` name by itself never proved the feature absent.

## Reproducibility

A local self-contained Python crosswalk tool consumed both existing `.tar.gz` archives. It validated the original futex.c SHA, 5/5 disassembly manifest text digests, original-image-relative contiguous instruction slots, 12 source semantic markers and 11 compiled instruction markers. Its **8/8 local unit tests passed**, including source and disassembly tamper rejection and negative evidence checks. This is a verified local offline analysis, not a GitHub Actions run or a new phone experiment.

## Hard limits and next meaningful evidence

- Exact source `rt_mutex_waiter` and `futex_q` lifetime-to-stack-slot mapping: **OPEN**.
- Relative on-device cross-syscall stack reuse and whether any intended primitive actually occurs: **UNVERIFIED**.
- Live kernel physical handoff, KASLR and device runtime privilege transition: **UNVERIFIED**.
- Stock Samsung signed-module enforcement, KDP/RKP/DEFEX, and KernelSU startup: **BLOCKED/UNVERIFIED**.
- No reason to repeat SHA-pinned firmware extraction, Clang offset parity, missing-symbol lookup or the five disassemblies merely to establish the above source correspondences.

Source-derived claims are distinguished from compilation inferences. This checkpoint does not label the HXL1 root path as functional.
