# SM-G986U1 HXL1 — independently decoded RT-mutex layout subset (2026-10-11)

## October 11 — original Samsung HXL1 WSL attestation completed

The owner executed the **committed** `tools/y2q_hxl1_rtmutex_displacement_attest.py` after `git pull --ff-only` from branch `feature/s20plus-investigation-shizuku-20261009`. Command supplied `--rea ~/HXL1-Stage3-REA-Evidence.zip`, `--slices ~/HXL1-Stage3-Code-Slices.zip`, and `--source ~/src/samsung-y2q-hxl1-stock` with report output `~/s20-artifacts/hxl1-research/rtmutex-source-layout-attested.json`. Actual WSL result:

```text
[PASS] compiled witness instructions: 31
[SOURCE] exact Samsung HXL1 header declarations checked
[REPORT] /home/main/s20-artifacts/hxl1-research/rtmutex-source-layout-attested.json
[LIMIT] subset; not OEM debug type layouts, root or KernelSU
```

**Accepted and closed in this narrow sub-gate:** 31 machine-word witnesses remain byte-exact; the two original pinned Samsung C file digests match, both local `rt_mutex` and `rt_mutex_waiter` declarations were identified in their expected member ordering and their original header hashes were saved. This validates exact-source header *identity/order*, not compiled struct `sizeof`, optional conditionals or factory debug layouts. The full JSON report remains only in the owner's WSL, so **specific recorded header SHA values have not been inspected in this remote commit** and are not invented.

The separate previously owner-observed authenticated `config.gz` states `CONFIG_RT_MUTEXES=y`, `CONFIG_FUTEX_PI=y`, `CONFIG_DEBUG_RT_MUTEXES` not set, `CONFIG_MODULE_SIG_FORCE=y`, and `CONFIG_KPROBES` not set; see the current execution guide. **Do not repeat stock firmware, compiled word or source declaration checks.**

**Next consequential gate:** Whether the existing vulnerable proxy-lock cleanup path can be reproduced within a safe, source-faithful, disposable guest and whether a legitimate kernel-code execution mechanism is possible despite the locked bootloader, force-signed modules and unavailable kprobes. Original Linux 4.19.325 guest boot success is *not* HXL1 vulnerability reproduction. No on-device race-triggering or destructive crash probes are approved by these results. Stage 3 overall remains PARTIAL and KernelSU deployment BLOCKED.

---

**Target:** `SM-G986U1`, `G986U1UESCHXL1`, stock kernel `4.19.113-27095354`.
**Evidence:** owner-provided `HXL1-Stage3-REA-Evidence.zip` and `HXL1-Stage3-Code-Slices.zip`, derived from original stock kernel SHA-256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.

This continues the 723/723 REA vs independent LLVM original-instruction agreement. A separately written v6 verifier asserted **31 additional compiled instruction witnesses**, passing **8/8 focused tests** on the uploaded evidence. No REA rerun, kernel compilation, original-phone operation, or GitHub action runner needed.

## Newly corroborated layout subset

| Type | Source-correlated member hypothesis | Binary displacement | Relevant original function-relative witness |
|---|---|---:|---|
| `rt_mutex` | `waiters.rb_root.rb_node` | `0x10` | `remove_waiter +0x54,+0xa8` |
| `rt_mutex` | `waiters.rb_leftmost` | `0x18` | `remove_waiter +0x18,+0xb0` |
| `rt_mutex` | `owner` | `0x20` | `remove_waiter +0x3c`; `rt_mutex_start_proxy_lock+0x84` |
| `rt_mutex_waiter` | `tree_entry` rb_node | `0x00` | `remove_waiter +0x48` |
| `rt_mutex_waiter` | `pi_tree_entry` rb_node | `0x18` | `remove_waiter +0x8c` |
| `rt_mutex_waiter` | `task` | `0x30` | `remove_waiter +0x138,+0x13c` via nested PI-tree pointer |
| `rt_mutex_waiter` | `lock` | `0x38` | `remove_waiter +0x18,+0x28,+0x2c` |
| `rt_mutex_waiter` | `prio` | `0x40` | `remove_waiter +0xd0,+0xe8` via direct vs PI-tree comparisons |
| `rt_mutex_waiter` | `deadline` | `0x48` | `remove_waiter +0x1e0,+0x1e4` via direct vs PI-tree comparisons |
| `task_struct` | `pi_lock` | `0x8c8` | `remove_waiter+0x80` |
| `task_struct` | `pi_waiters.rb_root.rb_node` | `0x8e0` | `remove_waiter+0x98,+0xc4` |
| `task_struct` | `pi_waiters.rb_leftmost` | `0x8e8` | `remove_waiter+0x138` |
| `task_struct` | `pi_blocked_on` | `0x8f8` | `remove_waiter+0x150` |

## Cross-path, compiler-byte assertions

The stock `remove_waiter` takes `x0=lock`, `x1=waiter`, then copies these into `x19` and `x23`. `ldr x22,[x0,#0x18]` selects a leftmost waiter, followed by `ldr x8,[x22,#0x38]` and `cmp x8,x19`, directly consistent with that waiter's lock pointer back-reference.

The PI waiter `task` field hypothesis is constrained by a nested pointer relationship: the owning task's `pi_waiters.rb_leftmost` is read from `owner+0x8e8`; it points at the waiter `pi_tree_entry` node at `waiter+0x18`. The compiled `ldr x1,[x8,#0x18]` therefore addresses `waiter+0x30`, consistent with the source-declared waiter task pointer.

Two separate priority accesses agree on `waiter+0x40`: the direct `[waiter,#0x40]` read and `[pi_tree_entry,#0x28]` (`0x18+0x28=0x40`). Deadline accesses likewise agree at `0x48`: direct `[waiter,#0x48]` and PI-tree-relative `[pi_tree_entry,#0x30]` (`0x18+0x30=0x48`).

These field names/ordering are corroborated by upstream Linux v4.19 `kernel/locking/rtmutex_common.h` and `include/linux/rtmutex.h` (`torvalds/linux`, tag `v4.19`). **That public upstream version is comparison context, not proof of the actual Samsung-patched headers.** The optional original-HXL1 source check can authenticate the exact local C file SHA pins and inventory original header member order, but it has not yet been run against those headers in this assistant session.

## Limits and next decision

**Stage 3 remains PARTIAL.** These are factory-derived *compiled instruction displacements with source-correlated identities*. A full structure layout, total `sizeof(rt_mutex)`/`sizeof(rt_mutex_waiter)`, hidden/conditional members, exact Samsung compiler provenance, and authenticated original DWARF/BTF remain unresolved. Branch-level cleanup observations do not prove an applicable exploit, root, bootloader unlock or KernelSU deployment. The source-verified header comparison is a next narrowly scoped step; do **not** repeat whole-kernel REA or stock firmware hashing.

The v6 Python verification code, tests and frozen report are packaged as `HXL1-Stage3-v6-rtmutex-layout-subset.zip` in the project conversation. User device was neither contacted nor modified.
