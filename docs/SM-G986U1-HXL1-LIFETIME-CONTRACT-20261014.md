# Galaxy S20+ HXL1 — source lifetime contract review

Date: 2026-10-14 (UTC). Input: owner-supplied `hxl1-source-dispatch-review.tar.gz` and `hxl1-disassembly-review.tar.gz`. Original `kernel/futex.c` SHA-256 matched the preserved Samsung HXL1 pin `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`. The supplied `fs/select.c` SHA-256 matched its newly recorded upload fingerprint `8b73f69f3f1929a39d7d7549f96cf6fa670420e140b9d67cae8177d1fe4642f3`; this fingerprint is **not independently certified against a preexisting factory pin**.

An independent read-only local audit verified **30 ordered source landmarks** (14 futex, 8 native select, 8 compat select) and reused the existing 5/5 disassembly digest and 4,102-instruction static CFG checks. **Ten synthetic regression tests passed locally**, including source tampering, changed source-marker ordering, duplicate/unsafe tar members, and unsupported compiled-stack claims. This tool does not contact the device, load code, rebuild a kernel, generate a payload, or alter firmware.

## Supported source-level findings

1. The exact Samsung source function `futex_wait_requeue_pi` declares local `struct rt_mutex_waiter rt_waiter` and `struct futex_q q` (source lines 3238 and 3241). It initializes the waiter, writes `q.rt_waiter = &rt_waiter`, performs futex setup and a wait, and later refers to the waiter for the proxy-lock and conditional cleanup paths. This establishes a **source-level address and lifetime relationship**. The previous code crosswalk strongly supports, but does not formally prove, source-helper expansion into `do_futex`.
2. Native `core_sys_select` declares the local `stack_fds` array and initially uses it as the six-bitmap backing store. When source `size > sizeof(stack_fds) / 6`, its separate path uses `kvmalloc`; afterward, the dynamic allocation is conditionally freed with `kvfree`. The saved original `core_sys_select` disassembly represents the native code, not the 32-bit compatibility implementation.
3. The source also defines `compat_core_sys_select`, a distinct path that uses `kmalloc_array` and `kfree` for the dynamic storage case. Do not equate that source path with the already archived native ARM64 function.
4. `SELECT_STACK_ALLOC` is referenced but **not defined by either of these two uploaded files**; no numeric source-threshold value is certified by this audit. Any number must come from the appropriate exact Samsung header/config provenance, not from another kernel.
5. Source paths can establish declaration, address-taking, wait/cleanup sequencing, and conditional allocation. They cannot authenticate the exact OEM compiler's C-local-to-stack-slot correspondence, address reuse across different system calls, exact runtime scheduling, or an executable exploit.

## Precise evidence boundary

| Gate | Result |
|---|---|
| Original futex source hash | MATCH |
| Uploaded select source fingerprint | MATCH TO UPLOAD ONLY |
| Source marker ordering | 30/30 |
| Previously archived disassembly integrity | 5/5 text hashes, 4,102 instruction slots |
| Local synthetic tests | 10/10 PASS |
| Actual compiled local-variable stack positions | **UNVERIFIED** |
| Cross-system-call stack reuse | **UNVERIFIED** |
| Exploitable GhostLock primitive | **UNVERIFIED** |
| Root or KernelSU on stock HXL1 | **NOT ACHIEVED** |

**Decision:** The missing-symbol, opcode-11 dispatch, entry-frame-size, and source-level lifetime questions have been sufficiently characterized to avoid rerunning them. The remaining execution-chain prerequisites require independent original compiler debug/code attribution and safe authorized device-level evidence, not assumed stack reuse from similar-sized frames. Stock module signature enforcement and Samsung KDP/RKP/DEFEX remain separate KernelSU acceptance gates.
