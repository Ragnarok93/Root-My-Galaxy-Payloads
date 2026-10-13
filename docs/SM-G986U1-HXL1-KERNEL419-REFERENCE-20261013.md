# HXL1: Linux 4.19 specific source compatibility vs K40 GhostLock reference

Reviewed on October 13, 2026 with the owner's exact Samsung source file archive
(`kernel/locking/rtmutex.c`, `kernel/futex.c`,
`include/linux/rtmutex.h`, `include/linux/sched.h`) and external repository
[`ccp-p/ghostlock-cve-2026-43499-4.19-k40`](https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40).

**Do not confuse two builds.** K40 upstream is Redmi K40 Snapdragon 870,
`4.19.157-perf-g9607d8651312`, Android boot header **v3**, and an OPPO/alioth
offset table. Owner HXL1 is Samsung SM-G986U1 Snapdragon 865,
`4.19.113-27095354`, exact `G986U1UESCHXL1`, boot header **v2**.
They share a Linux 4.19 series and related RT-mutex source behavior; they do
**not** share a proven ABI, runtime address space, shell permissions, or
bootloader/Samsung security constraints.

## Findings and compatibility changes

| Category | 4.19 reference observation | Safe HXL1 handling |
|---|---|---|
| rtmutex cleanup | Reference describes `remove_waiter` using `current->pi_lock` and assigning `current->pi_blocked_on=NULL` | **Source-confirmed** in owner Samsung `rtmutex.c` lines 1068–1080; `rt_mutex_start_proxy_lock` calls `remove_waiter` on error at lines 1797–1807. This is not runtime exploitation proof |
| futex | Reference discusses `futex_requeue` and proxy-lock rollback | Samsung `kernel/futex.c` contains `futex_requeue`; caller identity/branch reachability remains a separate static/dynamic proof |
| configfs callbacks | Reference uses 4.19 `configfs_read_file` / `configfs_write_bin_file` in `read/write` APIs | The enhanced provenance script probes those names **separately**; it never aliases them to `configfs_read_iter` / `configfs_bin_write_iter`. Exact original HXL1 symbols remain to be checked |
| ashmem | K40 reports no `/dev/ashmem` name prefix | Device/build-specific: do not copy prefix length or inferred `miscdevice.fops` offset from K40; existing HXL1 `0x10` remains provisional |
| allocation | K40 reports 3 kmalloc cache types and legacy pipe layout | Do not import K40 object sizes, SLUB geometry, or pointer offsets |
| security | K40 notes differences in `cred`, seccomp and SELinux structures | Samsung KDP/RKP/DEFEX/source configuration requires independent verification. No K40 cred, SELinux or seccomp bypass offsets are accepted |
| page/physical load | K40 has its own `P0_PAGE_OFFSET` and physical load conventions | Do not copy. Owner outer `abl.elf` is **ELF32/ARM**, while extracted `LinuxLoader-HXL1.efi` is AArch64 PE. Physical boot handoff remains unverified |
| waiter fields | The reference describes Linux 4.19 `rt_mutex_waiter` members | 0x00, 0x18, 0x30, 0x38, 0x40, 0x48 are **Clang10 comparison / Ghidra pointer candidates** in our owner study, **not** certified original OEM C member layout |

The upstream project's own `docs/status.md` marks the root-chain milestone
blocked and documents device-stage failures/partial evidence.
The README describes usage for a PoC but is **not a successful Samsung root
demonstration**. The target's `P0_PAGE_OFFSET` even differs across that project's
historical adaptation patch and current `target.h`, emphasizing the need to
pin the exact build. No whole upstream exploit or its K40 constants were imported.

## Integrated project tool

`tools/y2q_hxl1_kernel419_reference_audit.py` performs a *read-only* exact
Samsung-source check, hashes the two HXL1 C files, records independent callback
symbol spellings, and reports the source-level `current` vs waiter context.
It is **not** an exploit or a production profile generator.

```bash
cd ~/src/Root-My-Galaxy-Payloads && git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_kernel419_reference_audit
python3 tools/y2q_hxl1_kernel419_reference_audit.py \
  --source "$HOME/src/samsung-y2q-hxl1-stock" \
  --output "$HOME/s20-artifacts/hxl1-research/kernel419-source-reference-20261013.json"
```

Use a **new output filename** for any later run. This preserves historical
reports, original Image/bootloader files, generated headers and source.

The user's separately supplied `sm_g986u1_provenance.py` was also revised
in a downloadable stand-alone version:
`sm_g986u1_provenance_4_19.py`.
It preserves the source hashing and separate callback spellings, switches
bootloader-input selection to a verified ARM64 PE/COFF LinuxLoader instead of
interpreting outer ARM32 ABL as AArch64, refuses compilation with `PARTIAL`
definitions, blocks support-feed publication, and disables automatic evidence
cleanup. Seven local off-device regression tests passed. This stand-alone file
is not yet a production Root-My-Galaxy payload and is not used to assert
on-device CVE triggering.

## Acceptance state

Stages 1–2 COMPLETE; Stage 3 PARTIAL (0 factory-certified struct-member offsets);
Stages 4–6 OPEN; 7–8 BLOCKED; 9 DEFERRED. Neither the K40 PoC nor the HXL1
reference audit proves a Samsung privilege escalation or KernelSU deployment.
