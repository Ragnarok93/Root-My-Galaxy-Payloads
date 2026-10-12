# SM-G986U1 HXL1 — original Image early FDT >2MiB stop investigation

**Investigation date:** 2026-10-12. **Scope:** Isolated QEMU virt direct-boot of the original SHA-pinned Samsung HXL1 ARM64 kernel. No firmware or phone changes, no bootloader unlock or KernelSU, and no verified RKP secure pool.

## Direct original-kernel evidence supplied by the owner

- SHA-256 of immutable factory `kernel.bin`: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.
- QMP reported four matching `PC=0xffffff800a60514c` guest snapshots, CPU reported running EL1h, with `X16=X30=0xffffff800a605148`. Previous two-stage GDB independently verified original kernel entry `0x40080000` with `X0=0x48000000`.
- Source-grounded factory Image offset for the repeated PC, under the reconstructed VA base `0xffffff8008080000`, is `0x258514c`. Actual original bytes:
  ```asm
  ffffff800a605134: adrp x0, 0xffffff800a174000
  ffffff800a60513c: add x0, x0, #0x15c
  ffffff800a605144: bl  0xffffff800814f350
  ffffff800a605148: yield
  ffffff800a60514c: b   0xffffff800a605148
  ```
- The preceding call target `0xffffff800814f350` is the recovered, not independently live-symbol-validated `printk`. The nearest recovered function to the loop is `setup_arch` at `0xffffff800a604f88`.
- Static format pointer `0xffffff800a17415c` failed the original **plain-printable-ASCII** check. That check rejected control/newline characters and was not designed to decode the Linux `KERN_SOH` log-level prefix. The source program's `X13` and `X14` held independently printed ASCII fragments `heck you` and `r bootlo`. They are not alone enough to assert a complete error message.
- Owner original-image `setup_arch` source-loop audit: **15/15 unit tests PASS**; `PINNED_FACTORY_SOURCE_YIELD_LOOP_MATCHES_REPEATED_QMP_PC`; call target matches recovered `printk`; optional branch at `0xffffff800a605130` skips the loop.

## Strong upstream source match: invalid FDT boot error and 2MiB limit

Public ARM64 Linux source contains the `setup_machine_fdt()` path that maps the early FDT with `fixmap_remap_fdt()`; if this fails or `early_init_dt_scan()` rejects it, it prints a **device-tree error**, says the FDT must not exceed **2 MiB**, and deliberately executes `while (true) cpu_relax();`.

References for source-shape comparison (not certified exact Samsung HXL1 vendor source):
- https://android.googlesource.com/kernel/common/+/19b68814b1cd60c40546f31f7cc5b7895c0b013b/arch/arm64/kernel/setup.c
- https://gbmc.googlesource.com/linux/+/777747f634ba765085373f851e9c48dccb12ad52/arch/arm64/kernel/setup.c

The owner's v3 `-dtb` canary supplied an **input file of 1,048,592 bytes**, but actual QEMU guest FDT `fdt_totalsize` at kernel entry was **2,117,184 bytes (0x204e40)**, exceeding the 2,097,152-byte ARM64 early mapping budget by exactly **20,032 bytes (0x4e40)**. Its memreserve `[0x48000000,0x48205000)` covered those guest FDT bytes, proving delivery and self-coverage, but **does not make an over-limit FDT acceptable to early Linux**. The fatal-stop behavior, recovered printk call, original string fragments and oversized FDT strongly agree with an early `setup_machine_fdt` failure; exact HXL1 static format bytes and the original branch predecessor have not yet been confirmed.

**Do not interpret this as a bootloader unlock security check.** The upstream diagnostic asks that the bootloader supply a valid DTB; QEMU's direct loader, not the physical Samsung firmware, supplied the FDT in this experiment.

## Corrective experiment: compact only verified padding, no bypass patches

The new `tools/y2q_hxl1_qemu_fdt_size_recovery.py`:
- Rechecks the exact original generated `qemu-virt.dtb` SHA-256 `85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87` and the original 2GiB RAM semantics.
- Parses all FDT block boundaries from the original header, locates the memreserve terminator, computes the byte-end of the structure, strings and reservations, and **removes only unused zero-filled bytes beyond those sections**. Refuses nonzero trailing contents, inconsistent section sizes, source hash mismatch and existing unknown reservations.
- Preserves original structure/property bytes and reparses the entire compacted FDT.
- Adds a single FDT **self-reservation** with 2MiB upper bound at the previously measured guest FDT location `[0x48000000,0x48200000)`. This is diagnostic FDT-only memory, **not a free or secure RKP allocation**.
- Writes a *new* `compact-override.dtb` and exact-reconstruction manifest, never changes factory firmware. It does **not claim** what QEMU will deliver.
- The existing `tools/y2q_hxl1_qemu_memblock_pc_sampler.py` now accepts `--mode compact-canary`, verifies the compact DTB and manifest against the original SHA-pinned generated DTB, and runs a bounded isolated QMP PC/exception-state comparison. QMP register sampling alone does not validate a full runtime FDT's declared byte length; a later read-only kernel-entry guest FDT dump would be required to close that specific gate.

The original source-loop analyzer now also checks the source format bytes with an optional `KERN_SOH` log-level and embedded CR/LF/TAB in `candidateKernelPrintkFormat`, without allowing arbitrary control bytes or inventing a message.

## Owner procedure

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_setup_arch_loop_audit \
  tools.test_y2q_hxl1_qemu_fdt_size_recovery \
  tools.test_y2q_hxl1_qemu_memblock_pc_sampler

# Offline original OEM format-string inspection, unique saved output
python3 tools/y2q_hxl1_setup_arch_loop_audit.py \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-memblock-pc-samples-v3-20261012/setup-arch-loop-printk-v2.json"

# Offline exact original QEMU DTB compaction; fails closed if no zero slack
python3 tools/y2q_hxl1_qemu_fdt_size_recovery.py
python3 tools/y2q_hxl1_qemu_fdt_size_recovery.py \
  --verify-dir "$HOME/s20-artifacts/hxl1-research/qemu-fdt-under-2m-20261012"

# Read-only QMP PC sampling of separately validated compact DTB
python3 tools/y2q_hxl1_qemu_memblock_pc_sampler.py \
  --mode compact-canary \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-pc-compact-fdt-20261012"
```

**Correctness gate:** If the compacted input has no verified removable source padding, stop and inspect the original block layout. If a QMP run still stops in the same source loop, do not change kernel instructions or blindly escalate reservation size; recheck actual new runtime guest FDT bytes and the upstream `fixmap_remap_fdt` condition. If the PC progresses, no Linux boot or allocator exclusion is yet implied; next verify the complete FDT at kernel entry is <=2MiB and only then resume the original memblock callpath investigation.

## Status

- Original factory guest kernel entry and v3 custom FDT delivery: **verified**.
- Source `printk; yield; B yield` loop matching QMP PC: **verified in SHA-pinned factory file; live opcode mapping still not independently checked**.
- v3 QEMU delivered FDT over ARM64 2MiB cap: **measured and strongly explanatory**.
- Compact input artifact and live QMP behavior: **pending owner WSL run**.
- Linux memblock allocator exclusion, RKP protected pool, physical unlock, KernelSU: **unverified**.

## Owner compact-DTB result — original setup_arch fatal loop bypassed by valid smaller input

**Direct WSL owner evidence — October 12, 01:17 local paste.** `git pull --ff-only` brought the branch to `b990257`. The owner ran all **41/41** host tests in `tools.test_y2q_hxl1_setup_arch_loop_audit`, `tools.test_y2q_hxl1_qemu_fdt_size_recovery`, and `tools.test_y2q_hxl1_qemu_memblock_pc_sampler`, all PASS.

The reworked original factory Image message parser found, from original SHA-pinned factory Image offset `0x20f415c` (not from guessed upstream text), **KERN_SOH level 2** and exact diagnostic:

```text
Error: invalid device tree blob at physical address %pa (virtual address 0x%p)
The dtb must be 8-byte aligned and must not exceed 2 MB in size

Please check your bootloader.
```

This is now an **OEM original bytes confirmed** diagnostic emitted on the source `setup_arch` error path, not an OEM unlock command. The owner's original `ADRP+ADD` pointer and adjacent recovered `printk;yield; B yield` code match this log format.

The exact generated `dumpdtb` source originally occupied **1,048,576** bytes, including **1,041,008** bytes of *verified trailing zero slack* outside the FDT structure, strings and reserve-list terminator. The new input retained a compacted **7,568-byte** source plus a **16-byte** diagnostic memreserve entry: **7,584 bytes**. The input artifact SHA was **`1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd`**; the separate independent exact-reconstruction audit passed. It self-reserves `[0x48000000,0x48200000)` for the *runtime FDT only*; the source's reserved area is **not** a free/secure UH RKP memory pool.

The subsequent **real QEMU original-image** CPU sampling, using that verified compact input, returned:

```text
[PC OBSERVATION] GUEST_PC_CHANGED_ACROSS_SNAPSHOTS
[PC SERIES] ['0xffffff8008146ad4', '0xffffff8008146ae4',
             '0xffffff8008146ad4', '0xffffff8008146ae4']
[QEMU EXCEPTIONS]
...ELR 0xffffff80080a5794 (original Samsung SMC site)
...Data Abort ELR 0xffffff80082ac90c FAR 0x58
...Data Abort ELR 0xffffff80086de39c FAR 0x10
```

**Interpretation: comparative QEMU forward progress is directly established.** The former repeated early `0xffffff800a60514c` `setup_arch` invalid-FDT loop did **not** recur in the four sampled CPU PCs; the execution logged the **original known HXL1 secure-monitor callsite** and the two previously characterized fault sites. Thus correcting the FDT input size removes that *specific* early failure. This does **not** prove userspace boot, Linux memblock exclusion, functioning guest UH secure monitor ABI, or hardware root. The new sample PCs in `0xffffff8008146ad4/e4` may be another error-loop or post-fault handler; they are not proof of a healthy boot.

**Important remaining measurement:** The QMP sampler did not dump the actual FDT at the original kernel entry. Although the input is only 7,584 bytes, QEMU previously expanded the source FDT before delivering it to the kernel. The new **guest runtime** `fdt_totalsize` therefore remains **UNVERIFIED**. A robust read-only, factory-SHA-pinned halted kernel-entry capture is required before concluding the new guest FDT is <=2MiB.

### New bounded runtime size proof

New `tools/y2q_hxl1_qemu_compact_fdt_capture.py` rechecks both exact original kernel SHA and compact input source/manifest, starts paused isolated QEMU with the compact override and no NIC, stops at original kernel entry `0x40080000`, verifies `X0=0x48000000,X1=X2=X3=0`, and reads the *full FDT's declared size from guest big-endian header*. It reads only those bounded bytes, validates the raw dumped FDT, the exact GDB header and full-dump marker, original guest 2GiB RAM range, the unchanged diagnostic `[0x48000000,0x48200000)` memreserve entry, and reports whether **guest totalSize <=2,097,152**.

The tool keeps existing `qemu-pc-compact-fdt-20261012` and all prior source/guest evidence untouched. It never claims Linux allocator exclusion. The host unit test suite tests the exact 2MiB boundary, slightly over-limit/runtime-limit cases, rejected missing or mismatched header/markers and unexpected FDT reserve entries. Its **actual guest run still awaits owner WSL execution**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_compact_fdt_capture
python3 tools/y2q_hxl1_qemu_compact_fdt_capture.py \
  --output "$HOME/s20-artifacts/hxl1-research/qemu-compact-entry-fdt-20261012"
```

If the runtime header verifies within the 2MiB bound, future work should isolate **actual** secure-monitor operation and early Linux reserved-memory state *after* this specific FDT condition. The known SMC and FAR sites, rather than FDT-padding guesswork, are then the proper investigation targets. Do not patch out the valid early FDT size error loop or label this a Samsung bootloader lock test.


## Owner kernel-entry FDT size gate: PASS — 35,168 bytes

**Owner's actual WSL run, 2026-10-12 01:34 UTC:** after confirming the local `tools.test_y2q_hxl1_qemu_compact_fdt_capture` **15/15 PASS**, the owner executed `tools/y2q_hxl1_qemu_compact_fdt_capture.py` against the original SHA-pinned HXL1 kernel and the previously exact-reconstructed, 7,584-byte compact QEMU input device tree.

```text
[GUEST RUNTIME FDT BYTES] 35168
[ARM64 EARLY 2MiB] True
[CANARY FDT DELIVERY] DELIVERED_COMPACT_OVERRIDE_RUNTIME_FDT_WITHIN_2M
[RKP PROTECTED POOL VERIFIED] NO
[REPORT] /home/main/s20-artifacts/hxl1-research/qemu-compact-entry-fdt-20261012/compact-fdt-audit.json
```

The bounded GDB observer stopped at the **actual original ARM64 kernel entry `PC=0x40080000`**, verified `X0=0x48000000` and `X1=X2=X3=0`, captured the full guest header-derived `fdt_totalsize`, and required the **exact single diagnostic `[0x48000000,0x48200000)` FDT self-memreserve** and known 2GiB RAM interval. The original guest FDT is therefore **35,168 bytes**, which is **2,061,984 bytes below** the 2 MiB maximum. This is now proven by **guest evidence**, not by the compact 7,584-byte *input* file alone.

**Decision: close the original-kernel QEMU FDT image-size, entry delivery, alignment and diagnostic self-coverage research gate.** Do not generate additional FDT canaries or patch out the original `setup_arch` invalid-DTB error loop. The earlier owner QMP compact run reached the already-known Samsung SMC instruction at `0xffffff80080a5794` and reported two subsequent QEMU data-abort ELRs at `0xffffff80082ac90c` (FAR `0x58`) and `0xffffff80086de39c` (FAR `0x10`). No actual Linux memblock allocator-exclusion proof, UH/RKP hypervisor behavior, userspace boot, KernelSU, or hardware unlock follows.

### Next precise gate: correlate the saved secure-monitor and fault evidence

New `tools/y2q_hxl1_compact_exception_audit.py` is **strictly offline**. It independently revalidates the factory Image SHA, original generated QEMU DTB hash, exact 7,584-byte compact input/manifest reconstruction, owner's new complete 35,168-byte guest FDT and strict GDB header/entry audit, and the owner QMP capture's `compact-canary` source SHA. It parses bounded QEMU exception records from the **existing** `qemu-pc-compact-fdt-20261012/qemu-exceptions.log`, decodes ESR/FAR/ELR, links known site addresses to source factory Image bytes and nearest recovered symbols, and reports which original SMC and Data Abort ELRs are retained. It does not infer a functioning OEM secure monitor or repaired memory allocator.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_compact_exception_audit
python3 tools/y2q_hxl1_compact_exception_audit.py
```

The report will be written to a **new** `~/s20-artifacts/hxl1-research/qemu-pc-compact-fdt-20261012/compact-original-exception-audit.json`. Preserved original logs and kernel images are never overwritten.

