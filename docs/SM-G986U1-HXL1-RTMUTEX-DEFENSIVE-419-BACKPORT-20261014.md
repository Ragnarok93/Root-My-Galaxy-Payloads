# HXL1 Linux 4.19 — read-only CVE-2026-43499 remediation candidate (2026-10-14)

**Scope:** defensive review and source patch only. This is **not** a GhostLock trigger, an exploit port, a root procedure, an approved factory image, a KernelSU module or a production-feed artifact.

## Newly completed work

Reused the independently archived Samsung `remove_waiter-source.c` excerpt inside the owner's `rtmutex-stock-evidence.zip` (archive SHA-256 `ddc183a2fa7455a03052b5a843bc307b724a247c0bde381762ca6cafe47df648`). The source demonstrates that the proxy caller passes a queued waiter's target `task` while `remove_waiter()` locks and clears `current`. The prior [cross-task lifetime model](SM-G986U1-HXL1-CROSS-TASK-LIFETIME-AUDIT-20261014.md) already captures that source-level invariant; it is **not repeated** here.

The official upstream correction is [Linux commit 3bfdc63936dd](https://github.com/torvalds/linux/commit/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349), also recorded in the [Linux kernel CVE announcement](https://lists.openwall.net/linux-cve-announce/2026/05/21/7). The upstream code uses a newer `scoped_guard` locking helper that the reviewed 4.19 snippet does not use.

A **single defensive 4.19-source-compatible patch candidate** is staged at:

`research/y2q-G986U1UESCHXL1/remediation/0001-rtmutex-4.19-waiter-task-cve-2026-43499.patch`

It changes only `remove_waiter()`:
- obtains the target task identity from `waiter->task`;
- takes/releases **that task's** `pi_lock` while dequeuing and clearing `pi_blocked_on`, preserving stock raw-spinlock conventions;
- uses that same target identity as the priority-chain top-task argument.

No other caller is modified. Importantly, the existing separate fast-acquire return-`1` path and queue-validity assumptions remain outside the patch and require normal kernel regression testing.

## Validation performed

**PASS:** the candidate patch was generated from the exact archived `remove_waiter-source.c` function snippet, and `git apply --check`, `git apply`, and byte-for-byte comparison of the resulting corrected snippet all succeeded in a disposable local Git repository.

**NOT YET RUN / NOT CLAIMED:**
- `git apply --check` against the complete owner's Samsung 4.19 source checkout;
- actual HXL1 toolchain build, linkage or Samsung kernel ABI regression;
- lockdep/KASAN QEMU tests with kernel-native RT-mutex and PI-futex selftests;
- physical SM-G986U1 testing or any trusted firmware deployment.

## Owner-side safe next verification

Only test whether the patch matches the full stock source **without modifying it**:

```bash
cd ~/src/samsung-y2q-hxl1-stock
git apply --check \
  ~/src/Root-My-Galaxy-Payloads/research/y2q-G986U1UESCHXL1/remediation/0001-rtmutex-4.19-waiter-task-cve-2026-43499.patch
```

A successful `git apply --check` means only that the text context matches. It is not authorization to flash a modified boot image. Prefer a fully supported vendor/security update when available; the Linux CVE team notes that isolated fixes are not substitutes for a tested complete stable release.

## Readiness and security conclusion

The original factory source discrepancy is corroborated and the **source-only defensive fix** is now staged and fragment-tested. This adds no evidence of exploitability, no verified dangling dereference, no physical kernel handoff, no unlocked bootloader, no root and no KernelSU deployment. Stage 3 readiness remains PARTIAL until the repository's independent gates change.
