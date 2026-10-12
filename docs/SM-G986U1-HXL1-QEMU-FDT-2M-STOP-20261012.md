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

The owner's v3 `-dtb` canary injected a compact **source file of 1,048,592 bytes**, but actual QEMU guest FDT `fdt_totalsize` at kernel entry was **2,117,184 bytes (0x204e40)**, exceeding the 2,097,152-byte ARM64 early mapping budget by exactly **20,032 bytes (0x4e40)**. Its memreserve `[0x48000000,0x48205000)` covered those guest FDT bytes, proving delivery and self-coverage, but **does not make an over-limit FDT acceptable to early Linux**. The fatal-stop behavior, recovered printk call, original string fragments and oversized FDT strongly agree with an early `setup_machine_fdt` failure; exact HXL1 static format bytes and the original branch predecessor have not yet been confirmed.

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
