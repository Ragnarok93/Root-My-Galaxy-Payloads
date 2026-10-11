# HXL1 — QEMU device-tree override and memreserve self-canary

**Date:** 2026-10-11. **Purpose:** Prove whether `-dtb` delivers a custom FDT memreserve entry to the original factory kernel at its actual ARM64 entrypoint. **NOT a protected RKP pool, KernelSU deployment, verified guest Linux memblock state, or phone modification.**

## Exact owner-measured baseline

The owner has already run the original immutable SM-G986U1 factory Image with SHA-256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` on QEMU `virt,gic-version=3`, Cortex-A57, 1 vCPU, 2048 MiB guest RAM. The original generated DTB's SHA-256 is `85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87`, advertising RAM `[0x40000000,0xc0000000)`. The original guest stopped at `PC=0x40080000` and delivered the runtime FDT at `X0=0x48000000`, `X1=X2=X3=0`, with header size **1,048,576 bytes**.

At 22:46 UTC, the owner ran the full runtime-FDT capture and analyzer: **16/16 tests PASS**, and the actual `1 MiB` FDT was read completely from guest memory. Its declared-byte SHA-256 is `e842cd6cc6b7fc391420bd571dd0f9af3aec7f223101367ddcf14853bd3a7814`. Its raw bytes differ from `dumpdtb`, but **the inventory did not report differences** in `memoryRanges`, memreserve, `/reserved-memory`, `/chosen` initrd pointers, or node count. This does **not** prove full semantic equivalence of every FDT property. Both reported **zero** explicit memreserve and `/reserved-memory` entries.

The original Image candidate footprint `[0x40080000,0x443bb000)` does **not** intersect the real guest runtime FDT interval `[0x48000000,0x48100000)`, but is still a footprint hypothesis; the guest's early allocator and exact Samsung secure memory are not established.

## Why a self-canary instead of an arbitrary RKP carveout

Before claiming that a QEMU machine change can reserve UH memory, we must first demonstrate that an **FDT reservation entry survives the actual QEMU direct-boot path into the kernel-visible binary FDT**. The experiment deliberately reserves only the *already occupied* FDT location `[0x48000000,0x48100000)`. This tests entry propagation while **not** selecting a previously unverified RKP pool or assuming apparent gaps are unused.

The experiment does **not** reserve a new protected pool. Even a successful guest FDT memreserve entry would *not* yet prove Linux successfully installed a memblock reservation or that the RKP bitmap/allocators can use the pages. Independent memblock observation and source-correct secure-call memory effects would still be necessary.

## Committed tools and provenance guards

- `tools/y2q_hxl1_qemu_fdt_canary.py`: reads original generated `qemu-virt.dtb` with exact hash pin, refuses an already reserved source or changed RAM layout, inserts exactly one 16-byte big-endian FDT reserve map entry, updates the binary FDT header offsets, independently reparses its content and confirms no normal `/memory`, `/reserved-memory`, `/chosen` or node-count changes. Writes `canary-override.dtb` and `canary-construction.json` under a **new** evidence directory.
- `tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh`: verifies the original SHA-pinned kernel and the canary manifest **before** launching a 60-second-bounded local `qemu-system-aarch64` with `-kernel original -dtb canary-override.dtb`. At the original entrypoint it verifies `X0=0x48000000`, prints `X0-X3` and 16 header bytes, reads 1 MiB guest memory to `delivered-fdt.dtb`, and stops. It does **not** alter guest kernel bytes or access a handset.
- `tools/y2q_hxl1_qemu_fdt_canary_verify.py`: checks the original generated-FDT and baseline runtime-FDT hashes, reconstruction of the single FDT canary, recorded GDB marker/entry registers/header, full delivered DTB, exact memreserve entry and unchanged baseline RAM profile. It rejects unexpected guest reserves or drift in `/reserved-memory`.
- `tools/test_y2q_hxl1_qemu_fdt_canary.py`: 17 synthetic tests verifying the construction, rejection cases, script safety and delivery evidence. These tests are wired into HXL1 isolated CI.

**Current status:** Code committed; CI and owner-guest validation may still be pending until explicitly observed. A passing unit test **cannot** claim that QEMU has honored the external `-dtb` file.

## Owner WSL commands

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary

# 1. Read exact original QEMU-generated DTB and build a separate canary FDT
python3 tools/y2q_hxl1_qemu_fdt_canary.py

# 2. Start local QEMU only; halted GDB observes the external FDT
bash tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh

# 3. Compare the observed *guest* FDT with the source and prior baseline
python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py
```

Expected canary input output: `~/s20-artifacts/hxl1-research/qemu-memreserve-canary-20261011`.

Expected guest capture output: `~/s20-artifacts/hxl1-research/qemu-fdt-canary-delivery-20261011`.

**Each stage refuses to overwrite an existing output**; provide new paths through `--output-dir`, script arguments and verifier CLI options for repeat experiments. An unsupported `-dtb` path, relocated FDT `X0`, incomplete GDB read or missing canary is **INCONCLUSIVE/FAIL** for delivery, not a factory kernel failure.

## 22:53 UTC — owner guest dump exposed fixed-length truncation; corrected canary v2

Owner WSL verified all **17 original canary fixture tests PASS** and constructed an exact source SHA-pinned DTB with `[CANARY FDT] 85dcc18460e79d8543d0972a34c56844206696ea2030c7eb0f783412166fa440`, with the original fixed 1 MiB self-memreserve. The separate bounded QEMU/GDB capture printed **`[CAPTURE] Full guest FDT delivered at original entry via custom -dtb`**. However, the actual offline parser subsequently stopped:

```text
[STOP] Invalid declared DTB size
```

**This is an implementation defect, not a boot failure and not yet confirmed canary delivery.** The original source DTB may be 1,048,576 bytes; the canary inserts a sixteen-byte reserve-map record and increments `fdt_totalsize` to **1,048,592 bytes**. The old GDB script always dumped **exactly 1,048,576 bytes**, despite the larger header. Its success marker merely checked the fixed file length, so it **falsely labeled a truncated capture complete**. The original verifier also incorrectly demanded a 1 MiB guest file and required the complete FDT to fit within a stale 1 MiB self-reserve. Keep both the original canary and incomplete guest capture as evidence; never overwrite their directories.

**Corrected v2, committed directly through GitHub connector:**
- The canary builder reserves only the **4 KiB page-rounded bytes occupied by the modified FDT**, `align_up(fdt_totalsize + 16, 4096)`. For an original 1 MiB FDT that is **1,052,672 bytes**, `[0x48000000,0x48101000)`, covering one extra FDT page and *not* selecting an unrelated protected-memory pool.
- The second capture script uses GDB to read the **big-endian FDT header's declared size from guest memory** before choosing the binary dump length. It bounds the guest size to 8 MiB and available guest RAM, records both header length and actual completed read, and refuses success unless **dump file bytes == GDB declared size == FDT header size**.
- The independent verifier repeats these checks, compares the exact GDB evidence, enforces the newly page-rounded self-reserve, and explicitly diagnoses the old 1 MiB truncation.
- The synthetic fixture now models a full original 1 MiB DTB expanding by 16 bytes. Additional tests guard missing/mismatched measured size, truncated/oversized dump, partial self-reserve and the absence of any uncontrolled QEMU/kernel writes. Check CI before declaring the updated 23-test suite green.

Use distinct **v2 output directories**:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary

CAN="$HOME/s20-artifacts/hxl1-research/qemu-memreserve-canary-v2-20261011"
CAP="$HOME/s20-artifacts/hxl1-research/qemu-fdt-canary-delivery-v2-20261011"

python3 tools/y2q_hxl1_qemu_fdt_canary.py --output-dir "$CAN"
bash tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh "$CAN" "$CAP"
python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py --canary-dir "$CAN" --delivery-dir "$CAP"
```

If the new guest still moves its FDT, reallocates the blob, changes reservation properties, or reports size larger than the page-rounded reserve, the audit must fail with actual diagnostic evidence. A success proves only that the canary's reserve-map entry was delivered at the original kernel entry—not that Linux's memblock allocator installed a reservation or that any UH/RKP protected pool exists. The user's physical S20+ is never touched.

---

## What comes after canary success

1. Independently establish the actual early Linux memblock reserve behavior. A memreserve entry being present in the FDT at Linux entry is necessary evidence, not proof of allocator exclusion.
2. Determine a new protected pool location with a complete guest physical use map that excludes Image and BSS, runtime FDT and initrd, page tables, other vendor carveouts and QEMU loader regions; do not copy the fork's pool address.
3. Implement a QEMU-backed `hxl1_rkp_guest_commit` adapter with real guest MMU translation, source-matched RKP bitmap descriptor and atomic rollback. Only then attempt exact `UH_APP_RKP` command `0x15`; reject unknown commands.
4. Kernel userspace boot, on-device exploit, bootloader unlock and KernelSU remain separate unverified milestones.
