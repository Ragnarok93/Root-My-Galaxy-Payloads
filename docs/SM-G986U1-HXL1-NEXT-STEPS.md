# SM-G986U1 HXL1 — current porting execution guide

**Current October 11 REA FDT/boot-chain evidence:** [verified overlay composition, calculated FDT copy, boot/recovery component lookup, gzip classifier and remaining gates](SM-G986U1-HXL1-ABL-FDT-BOOTCHAIN-20261011.md). This research note supersedes earlier tentative names for `FUN_000228e0` and `FUN_00023a78`; root feasibility remains unproven.

## October 11, 23:57 UTC — QEMU -dtb canary delivered, guest FDT expanded beyond self-reservation

Owner WSL pulled through `50b2b65` and ran `tools.test_y2q_hxl1_qemu_fdt_canary`: **23/23 PASS**. V2 source FDT generated a diagnostic canary SHA `622103a0167457c0493dadc30979b3cc5aa630111df3970ab9ceb6eb1caae0b2` reserving the then-predicted FDT pages `[0x48000000,0x48101000)` (`1,052,672` bytes). **GDB then read the complete guest FDT, whose actual `totalsize` was 2,117,184 bytes**, not the 1,048,592-byte override file. The source-length assumptions failed again, but *not because of a truncated dump*: the new capture passed its exact-length GDB and header validation. The offline verifier then stopped only at:

```text
[GUEST DECLARED FDT BYTES] 2117184
[CAPTURE] Complete guest-declared FDT read at original entry via custom -dtb
[STOP] Canary does not cover the complete page-rounded FDT
```

Review of exact verifier control flow establishes the following **limited but real new fact**: the final error occurs **after** it successfully parsed the 2,117,184-byte guest DTB, verified the original stock image PC/X0/GDB full-read marker, checked the original generated and runtime FDT hashes, reconstructed the single canary, and required `guest["memoryReservationEntries"]==[expected_canary_reservation]`. Thus the custom `-dtb` canary entry **DID reach the guest**; the FDT self-reservation was merely **too small** to cover QEMU's expanded runtime FDT. Delivery has been proven; Linux's memblock allocator exclusion has **not**. This is **not** a kernel boot failure.

Actual guest FDT span is `[0x48000000,0x48204e40)`; it requires a 4 KiB-aligned diagnostic self-reservation of **2,117,632 bytes**, `[0x48000000,0x48205000)`. This is derived from **actual owner GDB data**, not a pool-selection guess. Neither address marks newly available RKP RAM; the whole interval is already occupied by the guest's FDT as declared in its header. No live Linux memblock/protected-pool observation exists.

**Committed follow-up:** `tools/y2q_hxl1_qemu_fdt_canary_verify.py` now has an explicit `--audit-delivery-only` mode that checks *all original proof gates* and writes `classification=DELIVERED_BUT_SELF_RESERVATION_UNDERSIZED` rather than suppressing the delivery finding. The default verifier remains strict on complete FDT self-coverage. `tools/y2q_hxl1_qemu_fdt_canary.py` now optionally takes `--self-reserve-bytes` with mandatory 4 KiB alignment, size bounds and no-RKP-pool declarations. Four new tests replay the exact **2,117,184-byte** runtime FDT and the observed 2,117,632-byte page-rounded reservation. New owner execution/CI status is pending until verified.

**Immediate offline replay (NO new guest run):**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary

python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py \
  --canary-dir "$HOME/s20-artifacts/hxl1-research/qemu-memreserve-canary-v2-20261011" \
  --delivery-dir "$HOME/s20-artifacts/hxl1-research/qemu-fdt-canary-delivery-v2-20261011" \
  --audit-delivery-only
```

If full FDT self-coverage is still a meaningful diagnostic, a **separate**, unmodified factory-kernel QEMU v3 run could construct a new `--self-reserve-bytes 2117632` canary and capture it in *new* paths. This cannot itself prove the early Linux memblock allocator reserved any memory. Next engineering priority is to inspect the original stock `/memreserve/` and early `arm64` `memblock_reserve` handling, then obtain allocator exclusion evidence before constructing a protected pool.

---

## October 11, 22:53 UTC — canary guest capture was truncated; v2 fixed and regression-tested

Owner WSL pulled through `0b616b0` and ran the original `tools.test_y2q_hxl1_qemu_fdt_canary`: **17/17 PASS**. It built the original diagnostic self-reservation `canary-override.dtb` with SHA `85dcc18460e79d8543d0972a34c56844206696ea2030c7eb0f783412166fa440`. The local original-image QEMU/GDB script printed a **false-positive full-FDT capture success** (its own condition only checked an unvarying **1 MiB dump**). The next offline verifier failed:

```text
[STOP] Invalid declared DTB size
```

**Verified in committed source:** adding an FDT memreserve entry increases `fdt_totalsize` by **16 bytes**. Given the exact baseline `1,048,576`-byte header, the canary needs **1,048,592 bytes**, whereas the original capture script dumped only **1,048,576 bytes**. Thus **the guest-delivery canary is NOT verified yet**; the message claiming a completed dump was invalid. The original evidence files are preserved, not overwritten. Also the old self-reserve length of 1 MiB did not cover its added DTB bytes; the correct minimal 4 KiB page-rounded self-reserve is `1,052,672` bytes (`[0x48000000,0x48101000)`). That interval is FDT-occupied, **NOT** a selected RKP protected pool.

**Fixes committed through GitHub:** builder rounds its reservation up to the complete augmented DTB's final occupied page; GDB reads the original guest FDT big-endian `totalsize` from `X0+4` and performs a bounded exact-length binary dump; the shell validates GDB reported total, captured file length and DTB header total as equal before reporting success. Offline verification independently checks the same requirements, with an explicit truncation error, manifest consistency and full self-reserve coverage. Six additional regression tests model the exact 1MiB+16 overflow. [GitHub Actions run #38182473039](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38182473039) completed **SUCCESS with 218/218 tests PASS**, including **23/23 updated canary tests**. The new v2 live QEMU capture on owner's WSL is **NOT YET RUN**.

**New owner command — preserve both old evidence directories and use fresh v2 paths:**

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

Only a passed *actual guest GDB FDT* verifier may establish that the FDT memreserve entry was delivered. Even then **Linux memblock behavior, guest reserved UH pool, guest MMU verification, Linux boot, bootloader unlock and KernelSU are still not proven**. The canary deliberately reserves only the FDT's own memory; it does not provide allocatable RKP pages. See [diagnostic self-canary v2](SM-G986U1-HXL1-QEMU-FDT-MEMRESERVE-CANARY-20261011.md#2253-utc--owner-guest-dump-exposed-fixed-length-truncation-corrected-canary-v2).

---

## October 11, 22:46 UTC — full runtime HXL1 FDT captured; reservation-delivery canary ready

The owner pulled the current branch and ran `tools.test_y2q_hxl1_qemu_runtime_fdt_compare`: **16/16 PASS**. A second, **bounded read-only QEMU/GDB** execution of the SHA-pinned original HXL1 factory Image captured the **complete 1,048,576-byte runtime device tree** at the previously measured guest `X0=0x48000000`, physically `[0x48000000,0x48100000)`. Owner's report:

```text
[GUEST FDT SHA256] e842cd6cc6b7fc391420bd571dd0f9af3aec7f223101367ddcf14853bd3a7814
[BYTE IDENTICAL TO dumpdtb] False
[SEMANTIC DIFFERENCES] [none]
[RUNTIME MEMRESERVE] 0
[RUNTIME /reserved-memory] 0
[KERNEL IMAGE OVERLAP] None
[RKP POOL RESERVED] NO
```

The **runtime FDT binary differs from the QEMU generated dump**, but the comparison's **limited** semantic inventory found no changes in memory layout, fixed/dynamic reservation entries, /chosen initrd metadata or node counts. These checks **do not prove all properties match**. We can now conclusively say the original guest at kernel entry received **no explicit FDT memreserve or /reserved-memory entries**, so its UH protected pool is still **NOT RESERVED**. This direct-guest result supersedes assumptions from `dumpdtb` alone.

**Progress beyond inventory:** committed a narrowly scoped `-dtb` **self-reservation delivery canary**, not a protected pool. `tools/y2q_hxl1_qemu_fdt_canary.py` adds exactly one FDT memreserve entry to an unchanged copy of the SHA-pinned generated DTB, covering the **already occupied FDT itself** (`[0x48000000,0x48100000)`), and proves no other FDT nodes, memory ranges, device properties or strings change. The separately bounded `tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh` uses `-dtb` to supply this diagnostic guest FDT while retaining the unmodified original factory `-kernel`; GDB captures the kernel's actual received FDT at the original PC with the original X0 and validates the full 1 MiB read. `tools/y2q_hxl1_qemu_fdt_canary_verify.py` cross-checks all original and delivered FDT hashes and requires the exact single canary to be present in the **guest** FDT. It still reports Linux memblock, UH pool and KernelSU unverified.

**Tests:** 17 new self-canary fixture tests and guard tests passed in successful isolated [GitHub Actions run #38182029643](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38182029643), **212/212 total tests PASS**. The **actual owner's -dtb delivery experiment is NOT YET RUN**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary
python3 tools/y2q_hxl1_qemu_fdt_canary.py
bash tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh
python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py
```

More details: [full HXL1 -dtb canary purpose, provenance and verification](SM-G986U1-HXL1-QEMU-FDT-MEMRESERVE-CANARY-20261011.md). A successful canary would prove **the FDT memreserve override reaches the guest entry**, not that Linux memblock honors it or that any free pages exist. Avoid selecting a real protected pool until physical occupancy/early memblock confirmation, and do not import the incompatible newer fork's `KDP_SET_NS_FLAGS` handler for HXL1 `RKP_GET_RKP_GET_BUFFER_BITMAP`. No physical phone change, bootloader unlock, root or KernelSU installation has been established.

---

## October 11, 22:34 UTC — genuine HXL1 kernel-entry FDT pointer and 1 MiB span confirmed

Owner WSL pulled through `b289dd0`, ran `tools.test_y2q_hxl1_qemu_entry_fdt_audit` **18/18 PASS**, executed SHA-pinned unmodified HXL1 Image inside bounded local QEMU/GDB, and received the exact boot-time device-tree header correlation:

```text
[ENTRY] GUEST_ENTRY_FDT_HEADER_CORRELATED
[X0-X3] {'X0': '0x48000000', 'X1': '0x0', 'X2': '0x0', 'X3': '0x0'}
[RUNTIME FDT CANDIDATE] {'start': '0x48000000', 'endExclusive': '0x48100000', 'sizeBytes': 1048576}
[IMAGE INTERSECTION] None
[PROTECTED MEMORY RESERVED] NO
```

This is **new actual guest CPU evidence**: GDB hardware breakpoint hit the original SHA-pinned ARM64 Image entry `0x40080000`, and live `X0` pointed to the expected big-endian FDT header magic with exactly **1 MiB declared FDT extent `[0x48000000,0x48100000)`**. `X1–X3` were zero as required by the ARM64 Linux boot convention. That runtime FDT span does **not** intersect the independently recorded *candidate, not physically attested* Image physical footprint `[0x40080000,0x443bb000)`. Previous `dumpdtb` still reported **no** FDT memreserve/`reserved-memory` and no actual protected RKP pool is established. The original 16-byte header **does not prove** the rest of the live DTB matches the generated dump or that Linux's memblock reserves anything.

**Added immediately:** `tools/run_y2q_hxl1_qemu_runtime_fdt_capture.sh` (separate bounded SHA-pinned local QEMU/GDB run, guest `X0=0x48000000` and `PC=0x40080000` gated, reads full 1,048,576-byte FDT into a new on-host file, no guest writes) and `tools/y2q_hxl1_qemu_runtime_fdt_compare.py` with 16 fixture/guard tests registered in isolated CI. The comparator checks new/old GDB breakpoint markers, all 16 header bytes, exact file length, the pinned generated FDT sha, runtime `/memory` and `/reserved-memory`/memreserve/`/chosen`, and avoids assuming runtime FDT is necessarily byte-identical to `dumpdtb`. One synthetic test initially failed because its expected error wording differed from the strict implementation; diagnostic corrected. **All 16 full-runtime-FDT tests PASSED**, and the full isolated HXL1 suite completed **195/195 OK** in [GitHub Actions run #38181271133](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38181271133). The real 1 MiB guest dump remains owner-pending. The full runtime FDT has **NOT YET BEEN CAPTURED on the owner's WSL**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_runtime_fdt_compare
bash tools/run_y2q_hxl1_qemu_runtime_fdt_capture.sh
python3 tools/y2q_hxl1_qemu_runtime_fdt_compare.py
```

Expected new artifacts: `~/s20-artifacts/hxl1-research/qemu-runtime-fdt-20261011/runtime-fdt.dtb`, `gdb-session.log`, `runtime-fdt-comparison.json`. If GDB times out or the guest read fails, retain the directory and use a **fresh** output path for any subsequent attempt, while passing `--runtime-dtb`, `--gdb-log`, `--output` as corresponding CLI overrides. The 1 MiB binary guest read is time-bounded to 60 seconds; a partial file is an **INCONCLUSIVE** capture, not guest boot failure. No pool is selected or reserved, the original Image remains immutable, and bootloader unlock/KernelSU are still unproven.

---

## October 11, 22:26 UTC — boot-memory audit passes; runtime ARM64 handoff FDT measurement

Owner pulled `22a1962` and ran `tools.test_y2q_hxl1_qemu_boot_memory_audit`: **15/15 PASS**, then ran the actual SHA-pinned factory original-image and QEMU-generated FDT cross-audit. Its observed output was:

```text
[STOCK] ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
[DTB] 85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87
[RAM BYTES] 2147483648
[RAM] 0x40000000 0xc0000000
[ORIGINAL IMAGE PROBABLE SPAN] 0x40080000 0x443bb000 status: POSSIBLE_QEMU_IMAGE_PLACEMENT_NOT_PHYSICALLY_ATTESTED
[FDT RESERVATIONS] 0
[PROTECTED POOL VERIFIED] NO
```

The **possible 67+ MiB stock Image span** at `[0x40080000,0x443bb000)` comes from the earlier trace-correlated kernel entry PC and the larger of the genuine Image file and ARM64 `image_size` header fields. It is **not** a measured complete guest-physical Image/BSS allocation or a verified gap. The dynamically generated `virt` DTB has **zero** explicit FDT reservations; the live early kernel's memblock/FDT runtime placements remain unmeasured. It is unsafe to select a UH RKP pool until early physical reservation is installed and confirmed.

**New targeted measurement code committed:** `tools/run_y2q_hxl1_qemu_entry_fdt_capture.sh` starts the same **SHA-pinned, unmodified** HXL1 Image on the proven `virt,gic-version=3`, Cortex-A57, 1 vCPU, 2 GiB guest profile, suspended with `-S`, and sets a localhost GDB hardware breakpoint at `0x40080000`. At the breakpoint it records `X0–X3` and reads **only the first sixteen bytes** at `X0`. Under the AArch64 Linux entry convention **X0 should contain the physical address of the boot-time device tree**. `tools/y2q_hxl1_qemu_entry_fdt_audit.py` validates the marker, entry PC, register values and big-endian DTB header magic/size, checks RAM bounds and possible overlap with the candidate Image, and **pins original Image + generated DTB provenance** to existing reports. Unknown/bad pointer, unreadable memory and missing breakpoint remain explicitly **INCONCLUSIVE**. No guest physical reservation, UH handler, memory write or phone action occurs. All **17 original synthetic guard tests passed in GitHub Actions run #38180648987 (178/178 full-suite tests)**. The 18th declared-DTB-padding regression also **passed**, and [GitHub Actions run #38180778127](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38180778127) completed **SUCCESS: 179/179 tests**, including all **18 entry/FDT tests**. The physical entry-point capture on the owner's workstation remains pending. The new owner GDB entry capture remains pending.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_entry_fdt_audit
bash tools/run_y2q_hxl1_qemu_entry_fdt_capture.sh
python3 tools/y2q_hxl1_qemu_entry_fdt_audit.py
```

Output: `~/s20-artifacts/hxl1-research/qemu-entry-fdt-20261011/{gdb-session.log,entry-fdt-audit.json}`; the prior boot-memory/DTB reports are preserved. This is a bounded **emulated guest** debug session, not an actual handset or a Linux userspace boot. Its result determines the next guest-runtime memory/DTB verification step. Bootloader unlock, RTmutex exploit and KernelSU deployment remain blocked and are not advanced by this guest entry observation.

---

## October 11, 22:21 UTC — actual QEMU virt DTB captured, no reserved RKP guest RAM

The owner ran `tools.test_y2q_hxl1_qemu_virt_dtb_inventory` **11/11 PASS**, and completed a no-kernel-execution stock-QEMU `dumpdtb` using the SHA-pinned HXL1 kernel and original `virt,gic-version=3`, Cortex-A57, 1 CPU, 2048 MiB RAM profile:

```text
[DTB] /home/main/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/qemu-virt.dtb
[DTB SHA256] 85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87
[MEMORY] /memory@40000000 0x40000000 0xc0000000
[RAM RESERVATION VERIFIED] NO
```

The actual generated `virt` FDT confirms one **2 GiB RAM range `[0x40000000,0xc0000000)`** and reports no explicit memreserve/`/reserved-memory` nodes in this bounded inventory. Importantly **this is NOT a free-RAM map**. The lack of memreserve does not exclude occupied kernel Image/BSS/DTB, loader allocations, page tables, early guest kernel stacks, runtime memblock allocations or temporary regions. It therefore **does not identify any safe RKP protected pool address**. Original guest RAM and firmware remain unmodified, and the root/KernelSU/bootloader gates remain closed.

**Next evidence-only code already committed:** `tools/y2q_hxl1_qemu_boot_memory_audit.py` and 15 synthetic regression tests in HXL1 CI. It cross-checks the **genuine** `kernel.bin` SHA and ARM64 header file/image size against the captured unmodified `qemu-virt.dtb` and its original hashed `qemu-virt-inventory.json`. The trace-correlated `0x40080000` Image PC is deliberately treated as a **candidate physical load base**, not an independently measured full physical footprint; the report lists the observed span and all missing boot-resource locations, never chooses a carveout, and marks guest memory reservation and real QEMU adapter readiness FALSE. All **15 new synthetic regression tests passed** in GitHub Actions run [#38180253727](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38180253727), contributing to **161/161 tests passing**. The owner's *actual original Image/DTB audit report* remains pending; passing fixtures is not physical footprint proof.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_boot_memory_audit
python3 tools/y2q_hxl1_qemu_boot_memory_audit.py
```

New output: `~/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/boot-memory-conflict-audit.json`. The audited data cannot justify setting `ram_reservation_verified=true` in `hxl1_rkp_guest_commit`. Before a genuine guest-memory SMC adapter, capture the actual loader/runtime FDT guest physical address and early memblock reservations, then independently install and verify a nonoverlapping reserved pool. **No additional QEMU boot is required for this audit.**

---

## October 11, 22:13 UTC — transaction WSL 9/9 PASS; QEMU virt generated FDT inventory tool

Owner pulled through `deff448` and ran `tools.test_y2q_hxl1_rkp_guest_commit`: **9/9 PASS**, with actual native-host C compilation and all injected write/rollback/readback failure fixtures. This independently corroborates 135/135 earlier successful CI tests. Entire original three-part host library is now **22/22 owner-validated** (7 pool + 6 staging + 9 transaction), but has **no real QEMU memory mapping, SMC handler or reserved physical pool**.

**New committed test-gated evidence step:** `tools/run_y2q_hxl1_qemu_virt_dtb_capture.sh` + `tools/y2q_hxl1_qemu_virt_dtb_inventory.py` and 11 synthetic regression tests, registered in isolated HXL1 CI. The shell script verifies exact SHA-pinned HXL1 factory `kernel.bin`, preserves existing outputs, and requests the QEMU `virt,gic-version=3` generated DTB with the same Cortex-A57, 1 vCPU, 2 GiB profile that hit the original SMC in GDB. `-S` and QEMU's `dumpdtb` property prevent intentional execution of the stock kernel; no on-device operation is involved. The parser is a bounded, pure-Python binary FDT reader that lists `/memory` regions, FDT memreserve entries, `/reserved-memory` fixed/dynamic nodes and initrd metadata, without interpreting gaps as available pages. The 11 new tests **passed in CI (146/146 total)** on run [#38179715298](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38179715298). Owner WSL DTB output remains pending.

Run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_virt_dtb_inventory
bash tools/run_y2q_hxl1_qemu_virt_dtb_capture.sh
python3 tools/y2q_hxl1_qemu_virt_dtb_inventory.py
```

Report: `~/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/qemu-virt-inventory.json`. **Do not select any guest-physical carveout based on absence from DTB reservations alone.** The inventory is a prerequisite to verifying a safely reserved protected pool; it is not sufficient. On failure/unsupported machine property, inspect `qemu-dtb-stdout.log` rather than executing an uncontrolled full QEMU boot. Full source ABI and memory contract are in [RKP integration proof gates](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md#2213-utc--transaction-confirmed-on-owner-wsl-qemu-virt-dtb-inventory-gate).

---

## October 11, 22:09 UTC — full isolated HXL1 workflow PASS (135/135)

After applying `libc6-dev-arm64-cross` to the isolated GitHub Actions workflow's AArch64 cross-compiler installation, [Actions run 38179184038](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38179184038) for commit `d8dac2e` completed **SUCCESS**. The fetched job logs report:

```text
Ran 135 tests in 3.787s
OK
```

This included **all nine new guest commit tests**: pointer-last publishing, dirty original pointer/preexisting reserved data refusal, fault injection, bytewise readback and rollback, all-vCPU quiescence and physical reservation gates, and the **partial original-pointer publication plus failed rollback** check. Prior workflow failures on two original-source AArch64 regressions were environmental (missing `bits/libc-header-start.h`), not RKP adapter failures. The cross-libc package fix has been validated by this full green run.

This confirms the existing original-source unit fixtures and all current host-only C interfaces compile and pass on `ubuntu-latest`. **It does not execute the factory HXL1 guest kernel in CI, implement real guest DTB/memblock reservation, prove an HXL1-compatible secure hypervisor, or install KernelSU**. The original owner-verified factory-image and SMC breakpoint logs retain their separate status.

**Next real emulator work:** inspect the exact `virt` generated FDT/device-memory ranges, reserve an actual candidate protected pool and descriptor backing before Linux memory initialization, implement vCPU-context guest VA→PA checks without hardcoded linear-map offsets, and wire the tested transactional commit layer into the HXL1-specific command-0x15 SMC handler. Do not use the upstream fork's `KDP_SET_NS_FLAGS` dispatch for the same numeric X0/X1; validate all further HXL1 commands against original source.

---

## October 11, 22:00 UTC — 13/13 host C tests PASS; guarded physical guest-memory commit layer

The owner executed the combined `tools.test_y2q_hxl1_rkp_pool_model` (7 tests) and `tools.test_y2q_hxl1_rkp_guest_stage` (6 tests) against current GitHub branch: **13/13 PASS**. Real host C builds, host pool ownership, sparse bitmap, 32-byte descriptor staging and synthetic mapping rejection are validated. Still **no guest physical reservation, MMU translation, original secure-monitor response, Linux boot or physical device access**.

New immediately committed implementation: `tools/hxl1_rkp_guest_commit.{h,c}` adds transactional *backend-agnostic* physical memory operations gated on verified guest mapping, all-vCPU quiescence and externally reserved memory. It snapshots original contents, rejects dirty/uninitialized states, writes the bitmap before the pointer table before the descriptor, updates original `rkp_s_bitmap_buffer` pointer **last**, validates every readback and restores attempted regions in reverse order after failure. A partially published kernel pointer followed by failed rollback is marked **uncertain/untrusted** and must halt guest emulation; it cannot be treated as safely reverted. **Nine** new synthetic C+Python regression tests were committed to HXL1 GitHub Actions; first eight transaction tests **passed in GitHub Actions** on 2026-10-11 22:06 UTC, while overall workflow failed due to a missing AArch64 libc sysroot in **older unrelated** source-slice tests. CI workflow now installs `libc6-dev-arm64-cross` to fix that known independent environment failure. New full-suite result still pending.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_rkp_pool_model \
  tools.test_y2q_hxl1_rkp_guest_stage \
  tools.test_y2q_hxl1_rkp_guest_commit
```

Read [source-derived RKP guest-memory boundary and rollback gate](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md#2200-utc--1313-owner-regression-pass-and-new-transactional-writer). The code is an internal library with a simulated memory backend, **not a ready-to-apply QEMU 10.2.2 patch**. Next engineering requirement is an HXL1-specific physically reserved QEMU `virt` RAM region backed by actual early guest page tables, with a verified kernel `X2` global pointer write through correct MMU-aware guest access. The existing Samsung production-QEMU `KDP_SET_NS_FLAGS` handler is incompatible with original HXL1 `RKP_GET_RKP_GET_BUFFER_BITMAP` and remains prohibited. Root/KernelSU/bootloader unlock remain blocked.

---

## October 11, 15:44 UTC — 7/7 host C pool tests passed; protected guest descriptor staging committed

The owner pulled `2bd6696` and ran `tools.test_y2q_hxl1_rkp_pool_model`: **7/7 PASS** including strict-warning C compilation, externally reserved pool checks, 4 KiB page alloc/reuse/double-free tests, and 1 GiB sparse bitmap boundary. This is the first empirically successful **native host C** version of the RKP memory model; it is **not** an HXL1 UH hypervisor or source-faithful QEMU boot.

**Immediately completed code:** `tools/hxl1_rkp_guest_stage.{h,c}`, `tools/hxl1_rkp_guest_stage_test.c`, and `tools/test_y2q_hxl1_rkp_guest_stage.py` plus HXL1 CI wiring. This stages a source-derived 32-byte descriptor, 64-bit `char **map` guest pointers, 1 GiB unit bytes and the global pointer slot `X2` as **HOST-ONLY** little-endian buffers. Every guest VA/PA relationship must be supplied by the adapter and validated through a mandatory callback; fake/overlapping/out-of-reservation mappings fail closed. No guest RAM writes, DTB changes, SMC interception or real physical page reservation are performed. **The new six-test staging suite has not yet been owner/CI-verified**. The complete [HXL1 RKP guest memory ABI and safety boundary](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md) now details the remaining genuine QEMU integration proof gates.

Next owner command:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_rkp_pool_model \
  tools.test_y2q_hxl1_rkp_guest_stage
```

**Do not** use synthetic staging addresses on QEMU, claim the upstream fork `KDP_SET_NS_FLAGS` handles the actual stock HXL1 `RKP_GET_RKP_GET_BUFFER_BITMAP`, or treat passing host tests as boot/root. To integrate, first capture a real original `virt` guest RAM map and verify protected-pool reservation in the device tree and kernel memblock, then check guest virtual-to-physical mapping and implement write atomicity. The stock handset and firmware remain untouched.

---

## October 11, 15:34 UTC — source-confirmed RKP preflight and host-only bitmap pool model

Owner pulled through `5707559` and verified the exact original-source RKP bitmap preflight: **14/14 unit tests passed**, and **14/14 source-specific checks passed**: commands `0x11–0x15`, 1 GiB bitmap sparse unit, descriptor fields `start_addr/end_addr/maxn/map`, physical/page bit offset logic, 4 KiB factory kernel pages, `paging_init` bitmap call before normal kernel mappings, later RO/DBL bitmap/init commands, protected page allocation/free consumers. The script accurately printed **`[FORK] NOT READY; protected pool and descriptor reservation unimplemented`** and saved `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-preflight.json`.

**Implemented and committed since that confirmed gate:** reusable QEMU-neutral host C model `tools/hxl1_rkp_pool_model.h` and `.c`, synthetic fixture `tools/hxl1_rkp_pool_model_test.c` and Python native-compiler regression runner `tools/test_y2q_hxl1_rkp_pool_model.py`, wired to isolated HXL1 CI. It models bounded aligned externally-reserved guest physical ranges (without actually modifying QEMU's DTB or memmap), 4 KiB page alloc/free with separate static protected membership bits, and host-only 1 GiB sparse-unit bitmap byte arrays; it does not write guest RAM, assign guest virtual pointer arrays or hook a secure-monitor call. **Ownership bitmap bit=1 convention is a model hypothesis, not measured UH firmware output**. Owner/CI pass for the newly committed C tests **has not been verified**; avoid promoting them to confirmed status.

Run only native C model tests (no QEMU/handset):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_rkp_pool_model
```

New integration contract: [HXL1 RKP QEMU pool boundary, source-derived ABI, and proof gates](SM-G986U1-HXL1-RKP-QEMU-POOL-BOUNDARY-20261011.md). Before integrating any SMC `0x15` handler, the actual guest reserved-memory carveout, correct `sparse_bitmap_for_kernel_t` guest VA/PA pointer chain, bitmap backing and non-overlap with Linux allocator must be independently implemented/verified. The public fork's app 2/command 0x15 **KDP namespace-flags** handler and generic fake-success path remain **explicitly incompatible**. Original factory kernel, kernel-source QEMU guest init, real futex race, bootloader unlock and KernelSU deployment remain separate unresolved milestones.

---

## October 11, 15:22 UTC — exact HXL1 bitmap ABI proven, next source-faithful emulation preflight

Owner verified **23/23 tests PASS** (5 GDB capture shell guards + 18 exact-source ABI regressions), confirming the prior test-order bug is fixed. The **actual original HXL1 source ABI audit** passed, producing `[HXL1 SOURCE] EXACT_LOCAL_SOURCE_DEFINITIONS_MATCH_CAPTURED_RKP_BITMAP_CALL`, **`X0=0xc300c002`**, **`X1=0x15`**, **`X2=0xffffff800a4dd0b8`** matching the recovered `rkp_s_bitmap_buffer` original symbol, and **`X3=0x40000000`**. This completes the exact HXL1 app-ID/command/argument source-correlation gate; no more SMC GDB capture is needed.

The newest source-based conclusion is **RKP_GET_RKP_GET_BUFFER_BITMAP**, **not** the newer Samsung QEMU fork's KDP_SET_NS_FLAGS, despite the fork using the same numeric X0/X1. The relevant public SM8250 `include/linux/rkp.h` also expects RKP commands `0x11–0x15` and a `sparse_bitmap_for_kernel_t` descriptor, whereas the fork implements different command values. This is an actual **ABI collision**; **NEVER import its KDP handler unchanged or assign universal success to unknown SMCs**.

**New code now committed:** `tools/y2q_hxl1_rkp_bitmap_preflight.py` with 14 source-gated synthetic regression tests and updated isolated HXL1 CI. It checks original local HXL1 `uh.h`, `rkp.h`, `arch/arm64/mm/mmu.c`, `init/main.c`, `arch/arm64/mm/pgd.c`; it compares the prior owner-validated source-hash and GDB ABI report to the unmodified files, then extracts RKP bitmap descriptor, 1GiB sparse indexing, PAGE_SIZE, paging init order and protected allocator requirements. Its owner/CI PASS is **pending**; not yet a validated firmware fact beyond the prior ABI proof. It does not run QEMU or alter guest hardware or the phone.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_rkp_bitmap_preflight
python3 tools/y2q_hxl1_rkp_bitmap_preflight.py
```

Fresh output: `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-preflight.json`. A perfect source witness report still reports QEMU adapter *NOT READY*, since the guest-physical bitmap backing and protected RKP allocation pool must be modeled and reserved independently. Next milestone after exact source preflight PASS is a deliberately isolated, HXL1-specific QEMU 10.2.2 fork component with **only** source-matched SMC dispatch, bounds-checked original sparse bitmap memory, and explicit rejection of unsupported commands. Kernel init, genuine protected page ownership, Linux userspace, bootloader unlock and KernelSU remain NOT VERIFIED.

See [QEMU adaptation and source verification](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1522-utc--exact-hxl1-source-and-rkp-bitmap-symbol-are-corroborated).

---

## October 11, 15:04 UTC — original HXL1 SMC guest registers captured; fork RKP/KDP ID conflict

The user ran the 13-unit secure monitor gate test group plus 5-unit QEMU GDB guard suite: **17/18 PASS, 1 FAIL** from a **test-only check-order defect**. The guard test expected existing-output rejection but its temporary HOME lacked the kernel image, and the shell checked for kernel presence first. GitHub code was fixed so existing output refusal precedes image checks, and original kernel SHA validation now precedes optional QEMU/GDB dependency checks. **The corrected suite's 5/5 owner/CI outcome is pending**, not claimed. The secure monitor gate analyzer itself PASSED and wrote `qemu-first-failure-20261011/secure-monitor-gate.json`.

The **actual original HXL1 guest GDB breakpoint succeeded**, capturing pre-SMC registers at the SHA-pinned factory `SMC #0` instruction `d4000003`:

```text
HXL1_SMC_BREAKPOINT_HIT PC=0xffffff80080a5794
X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000
X4=0x0 X5=0x0 X6=0x3f
```

**CRITICAL newly verified public-source vs fork incompatibility:** the upstream 10.2.2 Samsung production-QEMU fork classifies `X0=0xc300c002` as **KDP**, `X1=0x15` as **KDP_SET_NS_FLAGS**, and would write guest `vfsmount.mnt_flags`. But public **Samsung Snapdragon 865 Linux kernel source** `nwrafael/android_kernel_samsung_sm8250/include/linux/uh.h` defines `APP_RKP=2`, `UH_PREFIX=0xc300c000`, hence **the same X0 is `UH_APP_RKP`**. Its `include/linux/rkp.h` maps **X1=0x15** to **`RKP_GET_RKP_GET_BUFFER_BITMAP`** and invokes precisely `uh_call(UH_APP_RKP, 0x15, &rkp_s_bitmap_buffer, memstart_addr,0,0)` in `rkp_robuffer_init()`; X2 plausibly points at that global and X3 is QEMU's `0x40000000` DRAM start. This is the most specific stock guest boot-subsystem identification to date, **but the adjacent SM8250 source is not proof of exact HXL1 source mappings**. The fork's RKP commands `0x02/0x07/0x08` also differ from adjacent original source `0x11/0x12/0x13/0x14/0x15`. ***Do not reuse its KDP dispatch or generic fake-success SMC handler on HXL1.***

A new `tools/y2q_hxl1_rkp_bitmap_abi_audit.py` and 18 synthetic regression tests were committed and wired to HXL1 CI, but the owner has **not yet run** them. The audit hashes and inspects **their retained original HXL1 source** `~/src/samsung-y2q-hxl1-stock/include/linux/uh.h` and `rkp.h`, parses the already retained GDB `X0…X6`, and checks the approximate original `vmlinux-stock.nm` symbol for `rkp_s_bitmap_buffer` against `X2`. It records a source-specific ABI match or mismatch in `~/s20-artifacts/hxl1-research/qemu-smc-registers-20261011/rkp-bitmap-source-abi.json`. No additional emulator launches are necessary for this proof gate.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_qemu_smc_register_capture \
  tools.test_y2q_hxl1_rkp_bitmap_abi_audit
python3 tools/y2q_hxl1_rkp_bitmap_abi_audit.py
```

**Next major engineering task only after exact ABI match:** derive the correct `RKP_GET_RKP_GET_BUFFER_BITMAP` guest-side return side effect and sparse bitmap ownership, then narrowly adapt a private QEMU secure monitor emulator. Do not alter stock Image, invoke the fork's KDP namespace-flags writer, patch away SMC, return generic success, or flash the physical device. Linux userspace boot, valid HXL1 kernel RT-mutex runtime, unlock and KernelSU remain unproven. Full trace and fork compatibility matrix: [Samsung QEMU adaptation note](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1504-utc--gdb-captured-rkp-looking-bitmap-call-upstream-kdp-id-collision-discovered).

---

## October 11, 14:48 UTC — stock QEMU SMC #0 decoded; UH guest register capture gate

The owner ran the new original-image fault-site analyzer on WSL after `13/13 PASS` regression tests. It validated original stock HXL1 `kernel.bin` SHA `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`, found the three expected ELF-reconstructed Image offsets, and decoded actual original instruction words:

```text
ELR 0xffffff80080a5794 / offset 0x25794  opcode d4000003 -> SMC #0
ELR 0xffffff80082ac90c / offset 0x22c90c opcode f9402eb8 -> LDR X24,[X21,#0x58]; FAR 0x58
ELR 0xffffff80086de39c / offset 0x65e39c opcode a9412149 -> LDP X9,X8,[X10,#0x10]; FAR 0x10
```

**Major precision improvement:** The QEMU **Undefined Instruction** is a Samsung kernel **SMC #0** instruction hitting an unsupported/unhandled secure monitor path in the generic VM, rather than evidence for an unknown CPU ISA feature. The existing public Samsung-QEMU fork has a directly relevant `target/arm/tcg/op_helper.c:HELPER(pre_smc)` intervention supporting selected Samsung UH calls. However **X0…X6 were not captured**, so HXL1's exact secure-monitor application/command cannot yet be matched to its RKP/KDP dispatch (example fork IDs `0xc300c001`, `0xc300c002`). Do not blanket-stub all SMCs or copy another device's physical memory constants. Recovered nearest names `back`, `kmem_cache_alloc`, `dump_stack_minidump` are unverified symbols and cannot establish function membership or causal ordering. The two FAR values are consistent with null-base register accesses, but current register state is unmeasured and may not be causally downstream from SMC.

**Engineering work now committed:**
- `tools/y2q_hxl1_qemu_secure_monitor_gate.py`: exact original-kernel SHA gate, original ELR opcode checks, SMC/LDR/LDP decode, explicit `X0=UNOBSERVED` and near-null candidate reporting; **13 committed offline tests**.
- `tools/run_y2q_hxl1_qemu_smc_register_capture.sh`: one-shot **30-second** localhost-only QEMU+GDB hardware breakpoint at the original SMC ELR, meant to capture guest `X0…X6` without modifying the stock Image; cleans up the VM and prints **INCONCLUSIVE** when not hit. **5 committed guard tests**.
- Both suites enrolled in `.github/workflows/hxl1-cleanup-model.yml`. **Do not claim these new 18 tests pass until owner WSL or GitHub CI confirms execution**. The earlier owner-run 13/13 fault-site tests remain VERIFIED.

After pulling, run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_qemu_secure_monitor_gate \
  tools.test_y2q_hxl1_qemu_smc_register_capture
python3 tools/y2q_hxl1_qemu_secure_monitor_gate.py
bash tools/run_y2q_hxl1_qemu_smc_register_capture.sh
```

Review compact offline classification `qemu-first-failure-20261011/secure-monitor-gate.json` and GDB `qemu-smc-registers-20261011/gdb-session.log`. Only if `HXL1_SMC_BREAKPOINT_HIT` appears may `X0` be treated as an observed call identifier; confirm actual HXL1 source ABI before implementing a separately built Samsung-QEMU `pre_smc` adapter. If debugger miss occurs, inspect `gdb-session.log` and do **not** infer the factory kernel never reached the call. The stock handset remains untouched; source-faithful guest kernel init, real RT-mutex vulnerability, bootloader unlock and KernelSU deployment remain unproven.

See [Samsung QEMU adaptation note](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1448-utc--original-smc-0-identified-samsung-qemu-hypervisor-handler-selected-for-review).

---

## October 11, 14:38 UTC — QEMU original-kernel faults observed; image-relative opcode attribution

Owner successfully ran the direct Python CLI and **9/9** `y2q_hxl1_qemu_exception_summary` tests. Original 15-second generic-QEMU trace is **fully covered** at `216857` bytes. Its original SHA-pinned Image correlation still has `270` distinct matching offsets at `0x40080000`, with **0 mismatched opcode comparisons** in that report. Three `-d int` exceptions are documented:

```text
Undefined instruction: ELR 0xffffff80080a5794, ESR 0x02000000
Data Abort (read, L1 translation fault): ELR 0xffffff80082ac90c, FAR 0x58, ESR 0x96000005
Data Abort (read, L1 translation fault): ELR 0xffffff80086de39c, FAR 0x10, ESR 0x96000005
```

The original reconstructed vmlinux base **hypothesis** is `0xffffff8008080000`, giving candidate *Image-file-relative* offsets `0x25794`, `0x22c90c`, and `0x65e39c`. This VA base originates with `vmlinux-to-elf` reconstruction, not independently observed runtime KASLR. FARs `0x58`/`0x10` suggest bad/null-related pointer dereferences but do **not** yet prove a specific missing platform component. The first Undefined Instruction could be unsupported ISA capability or a deliberate trap; its exact stock opcode is needed. These exception events **do not** establish the last executed instruction or kernel init success, and no handset vulnerability/exploit/root is implied.

**Code delivered to GitHub:** new `tools/y2q_hxl1_qemu_fault_sites.py` with thirteen isolated unit tests, now included in HXL1 CI. It reads **existing** `exception-summary.json`, validates exact original `kernel.bin` SHA, decodes ESR, inspects original instruction words around the three ELRs and best-effort `aarch64-linux-gnu-objdump` disassembly, and correlates nearest recovered `vmlinux-stock.nm` symbols without claiming DWARF/factory provenance. Owner/CI results for this newly committed tool are not yet confirmed. See [Samsung QEMU adaptation report](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1438-utc-owner-qemu-exceptions--first-evidence-of-concrete-original-kernel-faults).

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fault_sites
python3 tools/y2q_hxl1_qemu_fault_sites.py
```

The new report `~/s20-artifacts/hxl1-research/qemu-first-failure-20261011/original-fault-sites.json` is created once only. **Next meaningful milestone:** classify the actual OEM faulting instruction and function at each ELR, then compare with the Samsung production-QEMU fork's supported CPU/UH/platform behavior. Do **not** blindly import Samsung memory carving, binary DEFEX/RKP bypass patches, or perform a new full QEMU build before this classification. Stage 3 PARTIAL, Stage 4 OPEN, guest kernel init OPEN, KernelSU BLOCKED.

---

## October 11, 14:11 UTC — QEMU offline exception-summary direct-script import fixed

Owner pulled through `e8b771c` and ran the **seven** `tools.test_y2q_hxl1_qemu_exception_summary` unit tests: **7/7 PASS**. Then invoking `python3 tools/y2q_hxl1_qemu_exception_summary.py` failed immediately with:

```text
ModuleNotFoundError: No module named 'tools'
```

**Cause:** Python directly launching a script within `tools/` uses the `tools` directory as a script import path; the code tried `from tools import y2q_hxl1_qemu_trace_attest as att` without first adding the repository root. This is a Python entry-point regression, **not a QEMU exception, incorrect stock Image SHA, or kernel boot finding**. The exception-summary tool never reached the owner evidence files and did **not** create its intended `exception-summary.json` report.

**Correction committed to GitHub:** only when run outside a package (`if not __package__`), prepend `Path(__file__).resolve().parents[1]` to `sys.path`. The module invocation form remains supported. Two new tests invoke the standalone script with `python3 -I` from an unrelated CWD, verify the CLI help imports and confirm that an existing JSON output is refused without overwriting it. The suite now contains **nine** tests. Their owner/CI pass has **not yet been observed**; do not claim otherwise.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_exception_summary
python3 tools/y2q_hxl1_qemu_exception_summary.py
```

This reuses the already captured and verified `qemu-first-failure-20261011` trace and `offline-trace-format-v2.json` report; no new virtual-machine execution, firmware extraction or on-device activity is needed. Next review the exception counts, translated-PC samples, unmatched opcode comparisons and candidate factory Image offsets, taking care that `-d in_asm` is a **translation** trace and does not establish a final executed PC.

---

## October 11, 14:01 UTC — original HXL1 instruction translation corroborated in QEMU

Owner-run evidence is a material stage improvement: **19/19 offline opcode-attestor regression tests passed** and the previously saved 15-second stock-QEMU trace produced:

```text
[EVIDENCE] FACTORY_IMAGE_INSTRUCTION_CORRELATION
[TRACE OPCODES] 11502
[BASE] 0x40080000 compared 288 matched 270 tail-matched 0 entry-word True
[BASE] 0x80080000 compared 0 matched 0 tail-matched 0 entry-word False
```

This supports **original stock factory Image code at guest PC 0x40080000 being translated by QEMU**: 270 distinct Image word offsets correlate with the SHA-pinned HXL1 kernel image, including offset zero. It is NOT a complete kernel boot, verified Linux printk output, an exact last-executed PC, a live-device primitive or KernelSU installation. QEMU `-d in_asm` emits **translated basic blocks**; it does not tell us whether those blocks executed to completion or establish the last executed PC. QEMU `-d exec` is different and records executed basic-block entries. The original trace contains only `in_asm,int,guest_errors,unimp`; there is no `exec` instrumentation in that existing run.

**New committed incremental read-only tool:** `tools/y2q_hxl1_qemu_exception_summary.py` and seven unit tests. It consumes the **already retained** `offline-trace-format-v2.json`, original trace, console and exact hashed Image, prints first/last sampled translated PCs, image correlation and mismatches, and bounds QEMU exception/guest-error lines (ESR/FAR/ELR when present). New summary JSON: `~/s20-artifacts/hxl1-research/qemu-first-failure-20261011/exception-summary.json`. The script NEVER reruns QEMU, mutates firmware, or contacts the phone. Test source and CI workflow are committed, but the new suite's WSL/CI result has not been verified yet.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_exception_summary
python3 tools/y2q_hxl1_qemu_exception_summary.py
```

**Decision:** If the retained log contains a specific exception, correlate its addresses and ARM64 syndrome with boot phase before reusing individual Samsung-QEMU fork platform handlers; if it does not, use narrowly bounded `-d exec,int` on a future isolated QEMU attempt only when the existing report proves insufficient. Do not assume that 270 matched original instructions imply a healthy console, scheduler, Android boot or RT-mutex execution. Stages 4–6 and KernelSU remain blocked pending later proof.

---

## October 11, 13:43 UTC — original trace format unresolved (zero parsed opcodes, not zero execution)

The owner reran the earlier QEMU offline trace analyzer: **12/12 unit tests PASSED**, but **zero opcode words were parsed** from the retained `qemu-first-failure-20261011/tcg-instructions.log`, giving **zero comparisons** at both candidate physical load addresses. The `NO_FACTORY_IMAGE_INSTRUCTION_CORRELATION_IN_SAMPLED_TRACE` label was **misleading** for this particular result: the analyzer never compared any decoded word, and the earlier first-failure report independently observed QEMU `IN:` translation-block markers. Actual factory Image execution, entry and Linux boot remain **UNDETERMINED**.

**Implemented and committed:** `tools/y2q_hxl1_qemu_trace_attest.py` now decodes QEMU's alternate `OBJD-T:` original guest byte stream with bare preceding `0xPC:` headers, explicitly excludes `OBJD-H:` host JIT code, recognizes whether a trace contains address-only lines without supported opcodes, and prints escaped first lines and translated PC candidates when no machine words parse. The regression suite was expanded to **19 tests**, including raw byte order, split `OBJD-T` chunks, host rejection, PC-only and unknown decoder formats; **these expanded tests remain unconfirmed on owner's WSL**. GitHub guide: [Samsung QEMU adaptation and trace rerun](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1343-utc--no-recognized-opcode-lines-trace-dialect-fix).

**Next action:** only run the corrected `tools.test_y2q_hxl1_qemu_trace_attest` suite and analyze the **existing** trace to a *fresh* `offline-trace-format-v2.json` file, preserving `offline-trace-attestation.json`. Inspect actual PC/hex bytes before changing virtual RAM, bootloader logic, security-hypervisor stubs, or launching another QEMU session. No physical handset access or new source rebuild is warranted.

---

## October 11, 13:28 UTC — traced QEMU timeout; offline Image-PC check queued

Owner ran the original-Image QEMU triage after pulling branch update: `tools.test_y2q_hxl1_qemu_earlyboot_triage` **8/8 PASS**; original Image SHA `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` and ARM64 `text_offset=0x80000` confirmed. The **actual** bounded QEMU run returned `[QEMU] TIMEOUT`, `[TRACE BLOCKS] True`, `[LINUX BANNER] False`. QEMU translated instructions, but original factory kernel entry has **not** been proven; no claim of kernel panic or boot is justified.

New **GitHub-committed, offline-only** `tools/y2q_hxl1_qemu_trace_attest.py` and `tools/test_y2q_hxl1_qemu_trace_attest.py` examine the existing 15-second trace log in bounded head/tail sections and match physical translated instruction PC/opcode pairs against the original SHA-pinned Image under explicit candidate load bases. Read [full run instructions and proof interpretations](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md#1328-utc-follow-up--offline-existing-trace-image-opcode-attestation). The test suite is wired into the existing isolated `.github/workflows/hxl1-cleanup-model.yml`; owner QEMU trace analysis **not yet executed**. If no candidate matches, review reported earliest PCs or supply a separately supported candidate physical base; do not initiate another 60-second silent QEMU run.

Until original factory ARM64 kernel Image execution/location is corroborated, **do not apply** the newer Samsung QEMU fork's hard-coded RAM/CPU/hypervisor/DEFEX settings to the Kona HXL1 guest. Stage 3 remains PARTIAL, Stage 4 physical handoff OPEN, KernelSU BLOCKED, phone untouched.

---

## October 11, 13:14 UTC — AArch64 user PASS, silent stock QEMU timeout, Samsung QEMU adoption

**Owner-observed results:**
- `gcc-aarch64-linux-gnu`, `qemu-user`, `qemu-system-arm` and `gdb-multiarch` now installed on Ubuntu 24.04 WSL. Direct AArch64 user emulation of the SHA-pinned `remove_waiter` *recompiled C fragment* PASSED: `[ARM64 USER] PASS`. Report: `~/s20-artifacts/hxl1-research/original-cleanup-arm64.json`. A `systemd-binfmt` trigger warning did not prevent direct `qemu-aarch64` execution.
- First `qemu-system-aarch64` stock original `kernel.bin` attempt (generic `virt,gic-version=3`, Cortex-A57, SMP2, 2 GiB) printed nothing for 60 seconds; GNU timeout exit `124`. There was **no TCG trace/GDB PC/early console**, so this is **no observable boot**, not a proven kernel crash or known entry point.
- The user explicitly requested reuse of existing public Samsung production-kernel QEMU work wherever beneficial. [Specific fork analysis, reuse matrix, and next bounded probe](SM-G986U1-HXL1-SAMSUNG-QEMU-ADAPTATION-20261011.md) inspect the actual `diabl0w/qemu-samsung-kernel` QEMU 10.2.2 patch and S26 references. Key warning: fork hard-codes a *different* SoC's high/low memory carveouts, UH/KDP semantics and AArch64 kernel load/physical assumptions. Do NOT blindly patch HXL1 or substitute its DEFEX policy. Do NOT simply execute `build-qemu-samsung.sh` at `-j$(nproc)` on resource-limited WSL.
- **New executable research tool committed:** `tools/y2q_hxl1_qemu_earlyboot_triage.py` and `tools/test_y2q_hxl1_qemu_earlyboot_triage.py`. It accepts only the original pinned HXL1 kernel SHA and ARM64 Image header, defaults to read-only plan, and on explicit `--execute` logs QEMU serial plus bounded TCG instruction/exception traces for a 15-second window. The tool and its synthetic fake-QEMU tests were added to `.github/workflows/hxl1-cleanup-model.yml`; **remote Actions pass has not been verified**.
- On receiving `qemu-first-failure-20261011/{report.json,serial-console.log,tcg-instructions.log}`, classify actual boot entry or the first guest exception. Port **only** a proven necessary, separately audited fork component with HXL1-specific address/memory/hypercall provenance.

**Readiness:** AArch64 user-space original source-fragment execution COMPLETE. Factory original ARM64 kernel boot, source-faithful guest, RT-mutex runtime reproduction, bootloader unlock and KernelSU remain unverified/blocked. Avoid re-running completed source/REA/instruction-window investigations.

---

## October 11, 12:50 UTC — OEM C fragment passed; original opcode store path additionally bounded

The owner's WSL source-fragment run PASSED the exact original Samsung RT-mutex SHA-gated native harness; **five unit tests passed, one optional ARM64 QEMU user test skipped** due to unavailable emulator/toolchain. Report: `~/s20-artifacts/hxl1-research/original-source-fragment-regression.json`. This fulfills the native verbatim-C fragment subgate only.

The assistant independently used owner-uploaded stock-Image-derived code-slice and REA ZIPs to authenticate the full `remove_waiter` slice and interpret a **15-original-instruction bounded path** to `str xzr,[x20,#0x8f8]`. Both synthetic task-identity cases and **6/6 tests** passed, including byte tamper rejection. [Detailed constrained original ARM64 trace](SM-G986U1-HXL1-BOUNDED-ORIGINAL-BINARY-TRACE-20261011.md). The reusable script/tests/report were delivered separately in `HXL1-bounded-original-ARM64-trace.zip` and are **not yet checked into this GitHub repo**. This interpretation does not execute OEM code in a real ARM64 CPU or faithful guest, and it does not verify any kernel exploitation path.

**Do not repeat these passing user-space/static tasks.** The consequential next feasibility decision is whether Samsung Linux 4.19.113 can be genuinely booted or otherwise safely executed in a source-faithful isolated guest, or whether an authorized live kernel-code-loading route exists. The installed upstream Linux 4.19.325 QEMU control is insufficient, and the locked stock build has forced module signatures and kprobes disabled. Stage 3 remains PARTIAL, KernelSU/deployment BLOCKED.

---

## October 11, 12:35 UTC — original Samsung C function fragment execution preparation

The owner executed the existing model on WSL at 12:30 UTC, with original Samsung C source SHA checks and ten compiled user-space scenarios `PASS`; report `~/s20-artifacts/hxl1-research/cleanup-model.json`. That model-only milestone is COMPLETE.

**New committed next step:** `tools/y2q_hxl1_original_cleanup_slice.py`, `tools/test_y2q_hxl1_original_cleanup_slice.py`, and CI additions to `.github/workflows/hxl1-cleanup-model.yml`. The tool extracts the **actual unedited `remove_waiter()` C function-definition text** from the SHA-pinned original Samsung RT-mutex source and compiles it in a disposable harness with mocked kernel helpers and a controlled no-owner early-return. Cases `current == waiter->task` and `current != waiter->task` check which synthetic task's blocked-on state gets cleared. Five isolated tests, including real C compilation and false-source SHA/modified behavior rejection, PASSED on a representative Linux 4.19-shaped fixture. Optional `aarch64-linux-gnu-gcc`/`qemu-aarch64` allows cross-compiled **ARM64 USER-MODE** execution; this is **not a kernel guest boot** and must not be described as one.

Owner-specific original Samsung C execution has **not yet been run**; [one-shot instructions and limits](SM-G986U1-HXL1-VERBATIM-CLEANUP-GUEST-SLICE-20261011.md). The exact Samsung RT-mutex C file SHA is enforced before compilation. A compiler error due to unmocked OEM dependencies is a **real harness compatibility block** to correct rather than an excuse to mark a PASS.

**No kernel-runtime gate is promoted by this source fragment.** Authentic Samsung `kernel.bin` execution in a source-faithful AArch64 Linux QEMU guest, real PI state corruption, a kernel arbitrary memory primitive, physical loader/KASLR verification, bootloader unlock and KernelSU code injection remain NOT VERIFIED/BLOCKED. Existing upstream 4.19.325 guest cannot substitute for HXL1; actual Samsung 4.19.113 has SoC/Kconfig constraints on the generic QEMU `virt` machine.

---

## October 11, 12:08 UTC — deterministic cleanup ownership regression (user-space only)

**Committed implementation:** `tools/y2q_hxl1_cleanup_regression.py` is a pinned-source-gated, ten-scenario **compiled user-space C state model**. `tools/test_y2q_hxl1_cleanup_regression.py` provides 8 isolated positive and negative regression tests. All eight passed in the assistant's host environment; the compiled C model also produced the expected ownership divergence for `waiter_task != current` and negative rollback return. An isolated GitHub Actions workflow `.github/workflows/hxl1-cleanup-model.yml` was committed to run these mock/source-independent unit tests on push and PR (remote Actions result **not yet independently confirmed**). [Execution instructions](SM-G986U1-HXL1-USERSPACE-CLEANUP-REGRESSION-20261011.md).

The model checks the same **two pinned Samsung source hashes** and **six source indicators** already defined by `tools/y2q_rtmutex_fix_audit.py` when run against the user's HXL1 WSL checkout. It compares a stock `ret != 0; selected_task = current` cleanup with a corrected `ret < 0; selected_task = waiter.task` and non-enqueued guard. It never invokes kernel futex calls, syscalls, races, device interfaces or kernel modules.

**Observed in compiled *simulation* (not an OEM execution):** on negative return, with different current/waiter task identities, the stock model clears current's PI-blocked flag while the corrected model clears the waiter's. On a zero return neither model cleans up; on a positive return the original nonzero branch still invokes modeled cleanup but corrected negative-only branch does not.

**Critical non-promotion:** passing model tests **does not** demonstrate that the HXL1 kernel executes the mismatched path under real Android scheduling, that the source is faithful in a disposable guest, that any arbitrary read/write primitive exists, or that KernelSU can load on the locked SM-G986U1. `sourceExactKernelGuestReproduced`, `hxl1RuntimeReachabilityProven`, `rootPrimitiveVerified`, `kernelSuInstallable` remain **false**. Original kernel assembly and source correlation documented previously is a separate proof category. Next necessary engineering gate is **actual HXL1-source-faithful guest execution**, not repetition of the model; if such a guest cannot be built/reproduced, the correct status remains `NOT_TESTED`.

---

## October 11, 11:43 UTC — authenticated subset of original RT-mutex and waiter displacements

A new offline pass reused the owner's previous original REA/ELF ZIP evidence and **independently reverified 723/723 Ghidra instructions against LLVM plus 31 specific additional byte-identical compiled RT-mutex/waiter instruction witnesses**. Eight focused full LLVM/subset tests and seven separately committed pinned-byte/source-header attestor tests passed locally (15 in total). Findings: `rt_mutex` candidate waiters.rb_root at `+0x10`, waiters.rb_leftmost at `+0x18`, owner at `+0x20`; `rt_mutex_waiter` candidate `tree_entry +0x00`, `pi_tree_entry +0x18`, `task +0x30`, `lock +0x38`, `prio +0x40`, `deadline +0x48`. The waiter priority and deadline each have **direct and nested PI-tree instruction pathways** that agree algebraically. See [the focused RT-mutex analysis](SM-G986U1-HXL1-STAGE3-RTMUTEX-LAYOUT-20261011.md).

**New runnable GitHub code** now committed: `tools/y2q_hxl1_rtmutex_displacement_attest.py` and `tools/test_y2q_hxl1_rtmutex_displacement_attest.py`. The attestor independently re-verifies the 31 pinned machine words and their ELF SHA digests, and has optional `--source` support to validate the **actual owner's exact Samsung HXL1 source** by pre-known RT-mutex/futex C SHA pins. It then records SHA digests, declaration order and conditional-member presence for `include/linux/rtmutex.h` and `kernel/locking/rtmutex_common.h`. See the [single-pass source checking instructions](SM-G986U1-HXL1-RTMUTEX-ATTEST-RUN.md). The full more general LLVM analyzer and frozen report are delivered as `HXL1-Stage3-v6-rtmutex-layout-subset.zip`, not yet in GitHub. Avoid repeated REA/bootchain/stock firmware inventory commands.

**Gate unchanged:** despite this meaningful compiled type subset, original factory DWARF/BTF and complete type sizes/conditional fields are not established; Stage 3 stays PARTIAL. No runtime read/write primitive, root or KernelSU demonstrated.

---

## October 11, 11:33 UTC — compiled member attribution and proxy-cleanup control flow

Verified **new Stage-3 subset** offline from the owner's two previously exported archives, without repeating REA or accessing a phone. The independent AArch64 decoder agreed on **723/723** REA-reported instructions; 38 annotated, exact code witnesses and 12 negative/positive opcode-and-attribution tests passed. See [the focused evidence report](SM-G986U1-HXL1-STAGE3-MEMBER-CORRELATION-20261011.md).

- `task_struct.pi_lock` candidate compiled displacement `0x8c8` relative to current (from `mrs sp_el0`) and relative to a separate masked owner pointer.
- `task_struct.pi_waiters` candidate `0x8e0` owner-relative; `task_struct.pi_blocked_on` candidate `0x8f8`, independently used with distinct current and owner registers.
- `task_struct.pi_state_cache` candidate `0x9f8` from futex cache load/store, **provisional** pending local exact-source behavior mapping.
- `rt_mutex_start_proxy_lock+0x34` takes cleanup on a nonzero return path, and `+0x44` directly calls `remove_waiter`. `remove_waiter+0x68` performs current-relative PI field clear. `remove_waiter+0x19c` passes current in `x5` to the next call. This matches the general source-level ownership bug review, not a demonstrated exploit.
- The assistant produced `HXL1-Stage3-v5-correlation.zip` (offline audit, original pinned-source optional checks, report, tests). The scripts are **delivered as an archive, not yet committed to GitHub**. Tests were executed in the assistant's container with the supplied archives; the exact local Samsung C file bytes were **not** uploaded. Prior owner-executed SHA checks attest those files, but this pass cannot independently compile full factory type layouts.

**Readiness unchanged:** Stage 3 PARTIAL pending independently authenticated full OEM type layout and runtime evidence. Stages 4–6 OPEN, KernelSU BLOCKED. No bootloader unlock, root, code execution on handset or flash.

---

## October 11, 11:24 UTC — independent complete slice bytes/LLVM crosscheck

The owner uploaded `HXL1-Stage3-Code-Slices.zip` containing three synthetic ELF64 AArch64 files from the already validated v4.2 run. This independent offline pass consumed the **three original REA JSON reports and manifest plus these three ELF files**, verified each entire ELF SHA-256 against the manifest, verified each `.text` SHA-256 against the manifest's saved stock-byte digest, and used a **separate LLVM AArch64 instruction decoder** (not Ghidra) to cover each four-byte location. This is a re-verification of the owner's saved exact-stock snapshot, **not direct access to the complete 52-MB factory Image or original factory DWARF**. No phone access or new REA was necessary.

| Original function | Slice bytes | REA reported/LLVM matching | LLVM-decoded slice slots | All 4-byte slots |
|---|---:|---:|---:|---:|
| `remove_waiter` `0xffffff8008147db4` | 568 | 140 / 140 | 141 | 142 |
| `rt_mutex_start_proxy_lock` `0xffffff8008147d14` | 160 | 38 / 38 | 39 | 40 |
| `futex_lock_pi` `0xffffff8008191984` | 2216 | 545 / 545 | 553 | 554 |
| **Total** | **2944** | **723 / 723** | **733** | **736** |

**New verification level:** zero mnemonic/operand differences for **all 723 reported REA instructions**, after explicitly normalizing only equivalent assembler notation (e.g. `b.cs` vs `b.hs`, hex vs decimal immediates, signed/wrapped ARM64 constants, register-index shift 0). Prior v4.2 had checked the independent objdump prefix of **16 instructions per function**; this separate pass extends comparison to the **entire reported instruction sets**. Test coverage: six isolated automated tests, including tampered ELF, tampered REA operand, and altered stock-manifest rejection, all PASS.

**All 13 REA-omitted words classified, not assumed to be gaps in OEM bytes:**
- `remove_waiter`: `+0x230` = `nop`; `+0x234` = undecodable `0x00be7bad`.
- `rt_mutex_start_proxy_lock`: `+0x98` = `nop`; `+0x9c` = undecodable `0x00be7bad`.
- `futex_lock_pi`: `+0x530` = `b +0x540`; `+0x538`=`ldr x26,[sp]`; `+0x53c`=`mov x27,x21`; `+0x540`=`mov w28,#0xbeff`; `+0x544`=`adrp x19,...`; `+0x548`=`movk w28,#0xdead,lsl #16`; `+0x828`=`b +0x804`; `+0x848`=`b +0x578`; `+0x8a4`=undecodable `0x00be7bad`.
The `mov/movk` pair would construct `0xdeadbeff` in `w28` if executed; **the runtime execution/reachability of these omitted instructions is not established**. The identical `0x00be7bad` final word in all slices is genuinely in the uploaded, manifest-pinned original bytes; its compiler/toolchain purpose is **unknown**. Six of the ten valid omitted instructions are clustered in `futex_lock_pi+0x538...+0x548`, outside Ghidra's non-contiguous function-body ranges; don't silently treat absent REA lines as undecodable instructions.

**Binary-derived ownership path, corroborated by independent decoder:**
- `remove_waiter+0x34` `mrs x20,sp_el0`; `+0x38` `add x21,x20,#0x8c8`; `+0x68` `str xzr,[x20,#0x8f8]` (current-task-relative store).
- At `remove_waiter+0x78`, `and x21,x24,#-0x2` **redefines** `x21`; subsequent `[x21,#0x8e0]` and `[x21,#0x8f8]` are relative to a *different* pointer. Conflating those displacements with current-task fields is invalid.
- `rt_mutex_start_proxy_lock+0x44` has a direct `bl` targeting the stock `remove_waiter` address when rebased out of synthetic ELF coordinates.
- `futex_lock_pi+0x30` obtains the task pointer from `sp_el0`, then `+0x78` and `+0xf8` load/store `[x20,#0x9f8]`, but **member identity remains unverified**.

**Proof gate remains PARTIAL:** These are independently verified **compiled displacement and static call-edge observations**, not a complete original `task_struct`/`rt_mutex_waiter` factory layout or proof of GhostLock execution, exploitability, physical memory access, bootloader unlock or KernelSU. Next productive work is source-level field/member attribution with an independent factory ABI provenance check; no more kernel-wide Ghidra imports or repeated firmware-provenance commands required.

---

## October 11, 11:15 UTC — uploaded Stage-3 REA archive analyzed offline

Owner submitted four files from successful v4.2 cache: `rea-slice-remove_waiter-ffffff8008147db4.json`, `rea-slice-rt_mutex_start_proxy_lock-ffffff8008147d14.json`, `rea-slice-futex_lock_pi-ffffff8008191984.json`, and `stage3-rea-correlation.json`. Independently checked JSON identity, instruction addresses, evidence IDs and isolated ELF SHA-256 links to the manifest; **the archive contains no original raw Image bytes or sliced ELF bytes**, so it does not itself support a second opcode-level re-disassembly. Source and stock bytes were checked on WSL by prior v4.2 pipeline; its independent disassembler comparison covered the **first 16 instructions per function**, not the whole recovered extent.

| Reconstructed stock function VA | Reported REA instructions | Total 4-byte positions in original slice | Not shown by REA | Coverage |
|---|---:|---:|---:|---:|
| `remove_waiter` `0xffffff8008147db4` | 140 | 142 | 2 | 98.59% |
| `rt_mutex_start_proxy_lock` `0xffffff8008147d14` | 38 | 40 | 2 | 95.00% |
| `futex_lock_pi` `0xffffff8008191984` | 545 | 554 | 9 | 98.38% |
| **Total** | **723** | **736** | **13** | **98.23%** |

Absent four-byte addresses, calculated from cached Ghidra coverage: `remove_waiter`: last 2 words at `0xffffff8008147fe4` and `0xffffff8008147fe8`; `rt_mutex_start_proxy_lock`: last 2 words at `0xffffff8008147dac` and `0xffffff8008147db0`; `futex_lock_pi`: nine positions (see locally generated archive audit). These may be padding, data or missing decoded code; classification **requires original bytes**, not assumption.

**Compiled source/ownership-path witnesses in `remove_waiter` (stock addresses are static recovered VAs, not runtime physical addresses):**
- At `0xffffff8008147de8` (function +0x34), `mrs x20, sp_el0`. Under this Samsung ARM64 current-task convention, it obtains the current-task pointer.
- At `0xffffff8008147dec` (+0x38), `add x21, x20, #0x8c8` uses a current-relative `0x8c8` displacement, consistent with the source `pi_lock` operation.
- At `0xffffff8008147e1c` (+0x68), `str xzr, [x20, #0x8f8]` explicitly zeros a **current-relative** field, consistent with source `current->pi_blocked_on`.
- At `0xffffff8008147e2c` (+0x78), `and x21, x24, #-0x2` overwrites `x21` with a different pointer. Therefore subsequent `[x21,#0x8e0]` and `[x21,#0x8f8]` references at `+0xc4` and `+0x150` **must not** be misclassified as current-relative; they are consistent with accessing PI state on a different task.
- At `rt_mutex_start_proxy_lock+0x44`, `bl 0x000100a0` in the slice resolves to `0xffffff8008147db4` in the original symbol map, the **direct call to `remove_waiter`**. Synthetic ELF branches reuse original AArch64 relative encodings; resolve with `original_function_VA + (synthetic_target - 0x10000)` rather than interpreting Ghidra display targets as real loaded addresses.

This establishes concrete reported *stock instruction-level displacement* candidates and the compiled cleanup call edge, strengthening the prior source-only ownership-path review. **It does not authenticate a complete `task_struct`/`rt_mutex_waiter` factory ABI**: source-level member attribution, adjacent register/control-flow propagation, absent words and the complete independent binary decoder check must be distinguished. `futex_lock_pi` also reads current-task-relative `+0x9f8` after `mrs x20,sp_el0`; the member identity is unverified.

**Next meaningful offline gate:** independently disassemble the 3 tiny preserved `isolated-*.elf` slices or the exact original byte ranges, compare 736 word positions and inspect the 13 missing REA addresses. Owner has already created these ELFs in the v4.2 cache. Do not rerun REA/Ghidra, rebuilt firmware provenance tests or compile the kernel. Stage 3 remains PARTIAL, Stage 4–6 OPEN, KernelSU BLOCKED. No root or phone action.

---

## October 11, 11:02 UTC — bounded-slice Stage-3 REA validated on owner WSL

The owner installed local v4.2 bounded-slice REA code and ran `python3 tools/y2q_hxl1_porting_pipeline.py --steps factory_abi` at 2026-10-11 11:00 UTC. Exact saved run: `~/s20-artifacts/hxl1-research/pipeline/run-20261011T110041993854Z`. The `factory_abi` script **PASSED** and generated `stage3-rea-factory-abi/stage3-rea-correlation.md`, showing all three symbols `remove_waiter`, `rt_mutex_start_proxy_lock`, `futex_lock_pi` in `INSTRUCTION_CORRELATED` / `MATCH` status. Stock kernel SHA256: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`; independently reconstructed analysis ELF SHA256: `e15f67e8253396d9e6463e5dfd78d67e324a7149842a7fbccb973ec0fd36ecdb`. The earlier 330000-ms whole-ELF REA import timeout was resolved by isolating bounded function ELF slices, rather than changing original firmware.

**Precise boundary:** v4.2's independent disassembler check compares the first 16 original instructions and source/image provenance. This verified milestone is not a full-function behavioral equivalence proof and does not authenticate `rt_mutex`/`rt_mutex_waiter` factory member offsets. A new *local-only*, separately packaged v4.3 cached-evidence audit scans **all REA-reported instruction addresses** in the existing v4.2 cache with an independent GNU AArch64 decoder; counts missing instructions and potential opcode/register/memory-operand discrepancies without rerunning REA or touching the phone. Its **nine isolated unit tests passed**, but the v4.3 full original-cache comparison has **not yet been run by the owner**, and the local code is **not committed** to this GitHub branch. Do not promote this to Stage-3 COMPLETE until independent compiled-layout/source-to-binary proof is available.

**Next engineering decision:** Evaluate v4.3 whole-slice coverage, then trace verified binary/source control-flow and operand provenance for the relevant existing functions only. Maintain strict separation of instruction encoding correlation, independently established factory field layouts, runtime address proof, exploitability, and KernelSU compatibility. No root/bootloader unlock/flash achieved.

---

## October 11, 10:49 UTC — REA provider timeout on reconstructed stock kernel ELF

Owner ran the v4 Stage-3 `factory_abi` pipeline; REA returned structured stdout JSON with `code=provider_timeout`, `operation=read_function_instructions`, `timeout_ms=330000`, and **empty stderr** for `remove_waiter` at recovered static `0xffffff8008147db4`. Saved as `~/s20-artifacts/hxl1-research/pipeline/run-20261011T103543343199Z/stage3-rea-factory-abi/rea-remove_waiter-ffffff8008147db4.partial.json`. This is a **whole-kernel import/analysis timeout**, not disproof of original source or proof of factory ABI.

A locally packaged (not yet committed to GitHub) v4.2 Stage-3 replacement eliminates automatic import of the entire recovered ~52-MB ELF for REA. It constructs each small ELF64 AArch64 function slice from SHA-256-pinned stock `kernel.bin`, cross-checks the entire slice with the recovered analysis ELF's executable segment, uses the next recovered symbol as a conservative boundary, caps the synthetic ELF code at 8192 bytes, and places the isolated function at `0x10000`. It then requires REA's evidence digest to match the synthetic ELF, translates REA addresses back to the authenticated original image-relative coordinates, and compares to GNU objdump. All 12 isolated unit tests passed, including real `readelf` validation, tamper checks and failure JSON diagnostics. This is **not yet an owner-executed v4.2 REA result**; wait for the actual WSL run before claiming it solved the provider timeout.

Old `rea-remove_waiter-*.partial.json` evidence is retained. New slices and reports use `isolated-*` and `rea-slice-*` names. Because ABI offsets cannot be inferred from truncated code and provenance-by-reconstructed-kallsyms alone, Stage 3 remains PARTIAL regardless of instruction matching. No kernel exploit, root, KernelSU or deployment supported.

---

## October 11, 10:21 UTC — offline HXL1 Pipeline v3 executed successfully

**Latest owner-executed WSL run:** `~/s20-artifacts/hxl1-research/pipeline/run-20261011T101520426839Z`. The previous **Pipeline v2** run reported all **10 underlying verification steps PASS** (stock firmware, boot v2, DTB inventory, FDT semantics, Stage-3 source layout, kernel proof matrix, ABL static handoff, RAM-partition protocol, pinned EFI/REA boot-chain evidence, and readiness). The subsequent **Pipeline v3** test suite completed **14 of 14 passing**, then independently generated `proof-ledger.md` from that saved successful run. Its output explicitly reports `OFFLINE CHECKS PASS=True` and `UNRESOLVED STAGES=[3,4,5,6,7,8,9]`.

**Distinguish success levels:** successful execution of all verifiers means tool integrity and pinned **static inputs**, **not** an installable payload. The official nine-stage readiness remains: stages 1–2 COMPLETE; stage 3 PARTIAL; stages 4–6 OPEN; stages 7–8 BLOCKED; stage 9 DEFERRED. The independent Stage-3 proof matrix inspected 85 retained **experimental Clang18** objects, finding **zero** complete `rt_mutex` and `rt_mutex_waiter` DWARF type definitions. This is a lack of verified factory layouts, not evidence those structures are absent from the kernel.

**Local implementation status:** The v1/v2/v3 pipeline scripts and proof-ledger modules were delivered to the owner as ZIP files, extracted into their local repository, and tested there. **They are not present on this GitHub branch**; `git pull` alone will not install or reproduce the runner until source is committed through an authorized workflow. Only these documentary observations are being synchronized here. Preserve `~/s20-artifacts` evidence and avoid cleaning original firmware while readiness is incomplete.

**Next actionable Stage-3 focus:** (1) inventory the original compiled ARM64 code and retained factory symbol/correlation evidence for the precise `rt_mutex` and `rt_mutex_waiter` members needed by any proposed target; (2) distinguish observed factory instruction offsets from source-only or experimental Clang18 DWARF declarations; (3) if factory ABI cannot be independently authenticated, record a specific `NO_VERIFIED_FACTORY_LAYOUT` blocker rather than using a guessed offset. Original runtime addresses, slide values and root-execution permission are separate later gates. Do not repeat DTB/protocol identification as a substitute for closing this gate.

**Hardware safety:** No bootloader unlock, root, KernelSU installation, phone modification, or kernel exploit was demonstrated by this run.

---

## Current priority — proven shared REA DTB/DTBO cmdline function (October 11, 2026)

**New, owner-executed REA/Ghidra findings on the SHA256-pinned original
`LinuxLoader-HXL1.efi`**:

| Stock string | Exact REA string xref source | Ghidra owning function |
|---|---|---|
| `androidboot.dtb_idx=` at `0xbfd99` | `0x2c350` | `FUN_0002bdf8`, entry `0x2bdf8` |
| `androidboot.dtbo_idx=` at `0xbfd82` | `0x2c308` | **the same** `FUN_0002bdf8` |

The previously verified source xrefs have REA evidence
`ev_b31e5021edd1b1d5db9ff58336bb5e0f0abc3ff1d8e2189e6ce93363a5c796db`
and
`ev_14dae88115f0805e73bc32804d89232d6212f4d3e65c777c335cd9ff09557a1b`.
The independent function reports have distinct evidence IDs
`ev_c2fd2200127d2a4bfef7b18a6ae80d09abcc09fe8d78e996af33dd3a635f51c4`
and
`ev_14f1e57b01fe90c2b5f6a15871dcf09b86d465d44550a7b7fcff5d97a393b81f`.
Both contain the source instruction within Ghidra's
`0x2bdf8–0x2cae3` function body and report available
HighFunction p-code.

**What this establishes:** the original binary's two
`androidboot` index strings are referenced by the **same**
cmdline builder. It does **not** establish whether it computes
the indices itself, reads globals or receives values from
the caller. The booted property values `dtb_idx=0` and
`dtbo_idx=2` are separate selection domains and do not
authenticate any particular offline base-FDT candidate or
DTBO overlay entry. No original standalone DTBO image was
found in the owner's filename-limited local artifact scan.

### Immediate next REA pass — reuse cached functions, trace once

Do **not** rerun `xrefs` or `function`. Both existing JSON
function reports reside in
`~/s20-artifacts/hxl1-research/abl-linuxloader/rea-dt-index-LBaPQ6`.
First display only the index-constructing pseudocode lines,
then invoke **the REA fork's native high-p-code value tracer
once** on the already proven shared function. Preserve output
and do not silently reuse incomplete traces:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

bash -euo pipefail <<'BASH'
OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
RUN="$OUT/rea-dt-index-LBaPQ6"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003

test -d "$RUN" && test -f "$REA" && test -f "$EFI" && test ! -L "$EFI"
printf '%s  %s\n' "$PIN" "$EFI" | sha256sum -c

python3 - "$RUN" <<'PY'
import re, sys
from pathlib import Path
from tools.y2q_linuxloader_rea_stage4_xrefs import parse_xrefs
from tools.y2q_linuxloader_rea_stage4_functions import validated

folder=Path(sys.argv[1])
specs=[
    ("dtb-index","0xbfd99","0x2c350"),
    ("dtbo-index","0xbfd82","0x2c308"),
]
reports=[]
for label,string_addr,source in specs:
    x=parse_xrefs(folder/(label+"-xrefs.json"),string_addr)
    assert x["sourceAddresses"]==[source],(label,x["sourceAddresses"])
    f=validated(folder,label,source)
    assert f["entry"]=="0x2bdf8" and f["pcodeAvailable"] is True
    reports.append(f)
    print("[VERIFIED]",label,f["entry"],f["evidenceId"])
assert reports[0]["body"]==reports[1]["body"]

lines=reports[0]["pseudocode"].splitlines()
hits=[n for n,line in enumerate(lines) if
      re.search(r"androidboot\.(?:dtb|dtbo)_idx",line)]
print("[CMDLINE INDEX LITERAL MATCHES]",len(hits))
shown=set()
for n in hits:
    for i in range(max(0,n-12),min(len(lines),n+17)):
        if i not in shown:
            print(f"{i+1:4}: {lines[i][:240]}")
            shown.add(i)
if not hits:
    print("[LIMIT] Pseudocode does not expose either literal; use saved raw evidence")
print("[LIMIT] Static cmdline formatting is not boot-time DTB selection")
PY

if test -s "$HOME/.nvm/nvm.sh"; then
  export NVM_DIR="$HOME/.nvm"
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
fi
if test -s "$OUT/rea-ghidra-env.sh"; then
  . "$OUT/rea-ghidra-env.sh"
fi

TRACE="$RUN/rea-shared-dtb-dtbo-native-values.json"
if test -e "$TRACE"; then
  echo "[PRESERVED EXISTING TRACE] $TRACE"
else
  PARTIAL="$RUN/rea-shared-dtb-dtbo-native-values.partial.json"
  ERR="$RUN/rea-shared-dtb-dtbo-native-values.stderr.txt"
  test ! -e "$PARTIAL" && test ! -e "$ERR" || {
    echo "[STOP] Prior incomplete native trace exists; review it first"
    exit 2
  }
  if node "$REA" trace-native-values "$EFI" 0x2bdf8 \
      --provider ghidra --json > "$PARTIAL" 2> "$ERR"; then
    mv "$PARTIAL" "$TRACE"
    echo "[REA TRACE SAVED] $TRACE"
  else
    echo "[REA TRACE FAILED; PARTIAL PRESERVED] $PARTIAL"
    sed -n '1,24p' "$ERR"
    exit 2
  fi
fi

python3 - "$TRACE" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
d=json.loads(p.read_text())
print("[TRACE FILE]",p)
print("[OPERATION]",d.get("operation"))
print("[PROVIDER]",d.get("provider"))
print("[EVIDENCE]",d.get("evidence_id"))
print("[ERROR]",d.get("error"))
n=d.get("normalized_result",{})
print("[RESULT KEYS]",sorted(n) if isinstance(n,dict) else type(n).__name__)
print("[LIMIT] A bounded p-code trace does not measure physical runtime state")
PY
BASH
```

REA's [native investigation contract](https://github.com/Ragnarok93/rea/blob/main/docs/native-investigation.md)
explains that `trace-native-values` follows HighFunction
def-use and statically resolved call arguments. Its built-in
budgets, pagination and omitted counts matter: absence from
one page is not proof of absent dataflow. Missing memory alias,
unresolved indirect calls, persistent-state updates and
boot-time inputs remain unknown.

**Next analysis decision:** inspect whichever operands feed the
two actual command-line value formatting calls in the decompile.
If they originate in a caller argument/global, follow the
authenticated producer with a *targeted* REA query. Do not
treat `FUN_0002bdf8` itself as the selector until the
dataflow proves it. Avoid unrelated kernel-debug/root
investigations while this narrow DT-index gate is open.

**Device safety boundary:** no Android device access, partition
write, exploit test, kernel load, privilege escalation or
KernelSU here. Symbol/structure work is still partial;
physical handoff and per-boot slide remain open and
KernelSU native integration remains blocked.

---

## Exact gate state, as of October 11, 2026

| PORTING.md | State | Verified already | What *actually* remains |
|---|---|---|---|
| 1. Exact firmware | COMPLETE | Owner ADB / Shizuku model, fingerprint, HXL1 kernel, locked bootloader, SELinux enforcing, shell UID 2000 | Recheck only after a firmware change |
| 2. Extract stock inputs | COMPLETE (offline originals) | Hash-pinned boot v2, ARM64 kernel Image, config, vendor source from 11 overlays, matching BL archive and parsed DTB streams | Only running-kernel/selected DTB identity is unproven; do not restart downloads |
| 3. Kernel symbols/layouts | PARTIAL, **active gate** | Recovered original Image ELF/NM, source fix review, 11 raw Image code windows; two Clang18 rtmutex/futex objects and internally consistent DWARF | Prove source-to-factory-instruction semantics and **independent factory-compiled** layouts; no original BTF/DWARF established |
| 4. Physical BL handoff | OPEN | Original ABL/XBL/XBL_CONFIG and Android boot-v2 fields; DTB candidates; some original EFI static flow | *Actually selected* boot chain/device tree and physical Linux load remain unknown |
| 5. Per-boot runtime metadata | OPEN | Device-specific non-root identity and some tracefs metadata | Device runtime slide, trace/worker and physical fingerprint details, where accessible; never import another device's constants |
| 6. Native target | OPEN | Firmware-locked inert Android diagnostic | Runnable HXL1 privilege chain, not just source code or Clang18 objects |
| 7. KernelSU | BLOCKED | Stock CONFIG_MODULE_SIG_FORCE=y, CONFIG_KPROBES=n, Samsung RKP/KDP/DEFEX | Proven code loading, kernel 4.19 hooking and OEM-specific compatibility |
| 8. App/feed | BLOCKED | Research-only identity gating | Actual hardware-verified secure integration; no HXL1 in `support/targets-v3.json` |
| 9. Recovery/release | DEFERRED | Original evidence retained | Repeatable owned-device recovery/testing before any risky execution |

**Treat the evidence source as immutable.** Original extracted
`~/s20-artifacts/kernel.bin` SHA256:
`ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.
The Clang18 two-object agreement is **experimental only**, *not*
a Samsung factory Clang10 ABI match. Even factory code-window hashes do
not themselves provide verified member offsets or runtime addresses.

## Do this next — one gate at a time

### A. Reconcile the documented nine-stage gates (run now)

In WSL2:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m unittest -q tools/test_y2q_porting_readiness.py
python3 tools/y2q_porting_readiness.py \
  --output "$HOME/s20-artifacts/hxl1-research/port-readiness-20261011.json"

cat "$HOME/s20-artifacts/hxl1-research/port-readiness-20261011.md"
```

**Pass:** tests pass; Stage 1 and Stage 2 COMPLETE; Stage 3
PARTIAL; Stage 4–5 OPEN; Stage 6 OPEN; Stage 7–8 BLOCKED;
Stage 9 DEFERRED; `payloadPortCompleted=false`.
If anything disagrees, investigate the *specific input*; **do not
mark a gate complete by editing the evidence manifest alone**. The
readiness utility is the status authority for the nine gates, not
how many auxiliary analyzers or Clang18 tests have passed.

### B. Review original compiled kernel vs original source (next active step)

Use the **already implemented** code-review tool, not another kernel
build, BTF extractor or new symbolic-analysis framework:

```bash
bash tools/run_y2q_hxl1_stock_rtmutex_source_code_review.sh
```

**Input:** the already created original
`~/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows-v2.json`,
hash-pinned original `kernel.bin`, `vmlinux-stock.nm`,
and original Samsung `kernel/locking/rtmutex.c` and
`kernel/futex.c`.

**Pass:** all 11 original code windows independently match actual
Image instruction words; original source hashes match; source
functions `remove_waiter`, `rt_mutex_start_proxy_lock` and
`futex_lock_pi` can be reviewed side-by-side. Save the write-once
`hxl1-stock-rtmutex-source-code-01.md`/JSON (or the next unused numbered
pair: `-02`, `-03`, etc. if a prior run already produced files).
The runner preserves existing reports rather than overwriting them.
An explicit `--out /path/to/report.json` is never auto-renamed and will
fail with the occupied filename if either JSON or Markdown exists.
**No source-level
operation has yet been proven to map to a specific factory structure
offset by this name-based report.** Review it before any new tools
or code are justified.

**Actual owner result (October 11, 2026):** The readiness tool passed
9/9 checks and classified stages 1–2 COMPLETE, 3 PARTIAL, 4–6 OPEN,
7–8 BLOCKED and 9 DEFERRED. The 11 original full-symbol-bounded
windows passed the source review (67/67 local tests); three
name-associated source definitions were found at original
`rtmutex.c:1068–1119`, `rtmutex.c:1797–1810`, and
`futex.c:2817–2998`. Their 192-byte code limits truncate
`remove_waiter` and `futex_lock_pi`.

The first report was already present, so the tool successfully wrote
`hxl1-stock-rtmutex-source-code-02.md` and JSON, but **then**
crashed while printing the terminal review because a summary-loop
variable overwrote the parsed `--show-review` arguments. The CLI
shadowing has been corrected with regression tests. **The existing
`-02.md` report is valid and need not be regenerated.** Use:

```bash
cat "$HOME/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-source-code-02.md"
```

Share this already-generated report for review before taking further
action; do not create a third redundant report merely for terminal
printing. Neither the report nor its disassembly proves factory member
offsets, exact full function semantics, boot relocation or root.

### C. Samsung FUS metadata check — optional, *not a new prerequisite*

The reference [`PORTING.md`](PORTING.md) uses
[`samloader-rs`](https://github.com/topjohnwu/samloader-rs)
to retrieve the **S721N/LUC** sample firmware. Those model/region and
four-part version values **must not** be copied for the S20+.

The original HXL1 kernel/boot/BL is already present and hash verified.
`samloader-rs` can query *currently available* official Samsung FUS
metadata, but `check-update --all` may not return an archived
HXL1 version, and a different currently offered build must not
replace the audited source or change the profile identity.

If `samloader` is already installed, **first determine the owner's
actual active sales/CSC code** from existing device metadata, then run:

```bash
samloader --version
samloader check-update --model SM-G986U1 --region ACTUAL_CSC --all --verbose
```

Replace `ACTUAL_CSC` **only** with independently observed CSC/sales
region (e.g. do not assume `XAA` simply because the model ends
in `U1`). This is a network firmware listing only. Do **not** run
`samloader download`, `flash`, `detect`, `reboot-download`,
or PIT/partition commands as part of this audit.
If the binary is absent or FUS omits HXL1, record
`FUS_HISTORICAL_LOOKUP_UNAVAILABLE` and continue:
existing original hash provenance remains intact.

### D. After B passes: identify the *specific* unresolved factory gate

Use the **already installed** tools for the actual gap:

- `llvm-objdump` / `aarch64-linux-gnu-objdump`, `llvm-nm`,
  recovered original `vmlinux-stock.elf` and source for
  static source-to-code examination. Use Ghidra *only if* bounded
  CLI disassembly is ambiguous and an address/branch-flow question
  requires it.
- `vmlinux-to-elf` has **already** been used. Its symbol recovery
  is not factory DWARF. `pahole` worked for our **Clang18-built
  objects**; their fields are not original layout evidence.
- Original `kernel.bin` had **no valid bounded raw BTF candidate**
  in the existing scan, and the reconstructed ELF exposes no
  original verified DWARF/BTF. `bpftool` is useful only if an
  **actual original BTF blob** is found; installing it alone cannot
  create original type information.
- Use existing HXL1 ABL/XBL, boot header and FDT reports for Stage 4,
  **after defining a specific physical-handoff proof question**.
  Static EFI RAM-region fields are not kernel load addresses.
- Use existing **read-only ADB/Shizuku** capability/identity probes
  for Stage 5 only when a concrete runtime question remains. Clearly
  distinguish `uid=2000` shell privileges from an ordinary app.
  Do not perform unsafe futex stress, kernel writes, or blind
  memory probing.

### E. Explicit stop/go policy

**Stop:** If factory field association or the kernel-loading chain
cannot be independently authenticated, record `UNVERIFIED`.
No more full Samsung kernel Image compilations, repeat Clang18 layout
extractions, speculative offset guessing, or redundant report
generators solely to inflate the completed-test count.

**Go:** Native device-specific implementation/KernelSU/app work can
only proceed after independent, reproducible evidence exists
for the exact shipping build and security constraints; do not
publish a support feed entry from stock source resemblance or
experimental DWARF alone.

## How we collaborate

Send the **Stage A readiness summary first**. If the nine states
are as expected, run **Stage B** and send the original source/code
excerpts (the runner prints them to the terminal). Review those
specific instructions, decide what they prove, then choose exactly
one next missing evidence gate. Do **not** execute all later stages
in advance.


## Current owner checkpoint — October 11, 2026

**Stage A passed**: 9/9 readiness tests and the exact expected
nine-stage statuses. **Stage B passed**: 69/69 source-code review
regressions; all eleven original disassembly windows and source SHA256
identities reverified. The owner preserved report
`hxl1-stock-rtmutex-source-code-03.md`.

A subsequent **direct original 568-byte** `remove_waiter` disassembly
captured all the major normal and exceptional branches through the
next recovered text-symbol boundary. Original stock instructions now
provide strong, source-consistent candidate associations for the
current-task PI lock, PI-blocked-on state, tagged lock owner,
and owner blocked-on-lock followup. The relevant original code SHA256
and precise provenance cautions are recorded in
[`ROOT_PAYLOAD_RESEARCH.md`](../research/y2q-G986U1UESCHXL1/ROOT_PAYLOAD_RESEARCH.md).
No original BTF/DWARF or factory debug member declarations have been
recovered; Stage 3 remains **PARTIAL**.

**Do not rerun Stage A/B, compile new Clang18 objects, or run a broad
script suite.** The next single check is a read-only lookup of
the **already-recovered** `vmlinux-stock.nm` for the actual branch/call
target symbol names, alongside original header declarations:

```bash
cd ~/src/Root-My-Galaxy-Payloads
NM="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm"
grep -iE '^(ffffff8008146ca4|ffffff80080fafb4|ffffff800996d544|ffffff800996d774|ffffff800996d664|ffffff800996d83c)[[:space:]]' "$NM" || true

STOCK="$HOME/src/samsung-y2q-hxl1-stock"
grep -nE -C 4 'struct rt_mutex_waiter|struct rt_mutex \{|pi_lock|pi_waiters|pi_blocked_on' \
  "$STOCK/include/linux/rtmutex.h" \
  "$STOCK/include/linux/sched.h" | head -n 120
```

If all or some target names are missing, record the omission;
do **not** manufacture or import a substitute from a different
device. Inspect those precise branch destinations using the existing
recovered Image and disassembler only when essential. Distinguish
original machine-code member-location candidates from independently
established complete factory layouts. Continue only after evaluating
this output, then select one remaining proof gap.


### Owner checkpoint: stock `remove_waiter` call graph verified

The owner's next read-only WSL check resolved **all six** selected
original stock static-call destinations in
`vmlinux-stock.nm`: `rt_mutex_adjust_prio_chain`,
`rt_mutex_setprio`, `_raw_spin_lock`,
`_raw_spin_lock_irq`, `_raw_spin_unlock`,
and `_raw_spin_unlock_irq`. Original headers also confirm the
presence and ordering of `rt_mutex.wait_lock/waiters/owner`
and `task_struct.pi_lock/pi_waiters/pi_top_task/pi_blocked_on`.

This completes the **targeted original call-identity check**; do
not rerun it. It strengthens source-to-factory-instruction evidence,
**not** complete factory field-layout provenance or root feasibility.

**Next one evidence gate — original nested RT-mutex/waiter declarations:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
STOCK="$HOME/src/samsung-y2q-hxl1-stock"
for src in \
  "$STOCK/kernel/locking/rtmutex.c" \
  "$STOCK/kernel/locking/rtmutex_common.h" \
  "$STOCK/include/linux/rtmutex.h"; do
  if [ -f "$src" ]; then
    echo "===== $src ====="
    grep -nE -C 10 \
      'struct rt_mutex_waiter[[:space:]]*\{|rt_mutex_top_waiter\(|rt_mutex_owner\(|task_blocked_on_lock\(' \
      "$src" | head -n 175
  fi
done
```

Review only which original structures, inline helpers and pointer
relationships the stock `remove_waiter` accesses can corroborate.
A source-level nested definition, even with these corroborating
machine instructions, does not authenticate *every* packed/aligned
member in the OEM compiled binary. Retain Stage 3 **PARTIAL**
and continue to Stage 4–5 runtime-evidence prerequisites as
independent gates only when there is a specific remaining proof
question. Nothing here authorizes kernel memory writes or a
KernelSU support-feed entry.


### Completed: Original waiter/helper correlation (owner WSL verification)

Owner confirmed the exact original `rtmutex_common.h` source
defines `struct rt_mutex_waiter`, the `rt_mutex_top_waiter()`
cached-first-node and `BUG_ON(w->lock != lock)` path, the
tagged `rt_mutex_owner()` accessor, and
`task_blocked_on_lock() -> p->pi_blocked_on->lock`.
These source relationships fit the original stock `remove_waiter`
load/branch chain: `lock+24` top cached waiter,
`waiter+56` lock pointer, `lock+32` owner pointer,
and owner/current task PI accesses near
`+0x8c8`/`+0x8e0`/`+0x8f8`.
Conditional `CONFIG_DEBUG_RT_MUTEXES` layout changes remain
a separate verification requirement for any field after the
optional debug members, such as `prio`.

**Stop looping on RT-mutex structure scans.** The selected
source-to-binary operation correlations are now sufficiently
documented as observations, but the **complete OEM ABI remains
PARTIAL**. They do not provide arbitrary kernel read/write,
a runtime kernel pointer or a valid KernelSU loading path.

### Next gate: review *existing* Stage 4/5 evidence, not a new sweep

The exact original ABL LinuxLoader static handoff was already
documented, and the prior device-side, read-only ADB evidence
did not measure the actual UEFI `KernelBaseAddr`/base-memory
branch, KASLR value, physical kernel entry or confirmed
booted DTB. Rather than rerun that denied/restricted probe,
read the retained results and identify whether the device
exposes a new legitimate source of runtime evidence:

```bash
cd ~/src/Root-My-Galaxy-Payloads
BASE="$HOME/s20-artifacts/hxl1-research"

echo "=== Existing Stage 4 static handoff ==="
sed -n '1,115p' "$BASE/abl-linuxloader/rea-stage4-handoff-static.md"

echo "=== Already retained live ADB reports (do not re-probe) ==="
find "$BASE/live-adb" -type f -name live-boot-evidence.md -print 2>/dev/null |
  sort | tail -n 5

echo "=== Exact HXL1 signed-module/kernel-probe gates ==="
gzip -dc "$HOME/s20-artifacts/config.gz" |
  grep -E '^(CONFIG_MODULES=|CONFIG_MODULE_SIG_FORCE=|CONFIG_KPROBES=|# CONFIG_KPROBES is not set|CONFIG_RT_MUTEXES=|CONFIG_FUTEX_PI=|CONFIG_DEBUG_RT_MUTEXES=|# CONFIG_DEBUG_RT_MUTEXES is not set)' || true
```

**Decision:** With no new independent runtime evidence,
do **not** claim a physical load/KASLR number, GhostLock
exploitation, root or KernelSU. Existing forced module-signature
checks and `CONFIG_KPROBES=n` must be treated as real design
obstacles. The next engineering milestone is *feasibility of
an authorized runtime privilege/code-loading primitive on the
exact locked HXL1 build*, not another Clang18 object or
truncated disassembly. Stage 7 stays BLOCKED.


## October 11 owner checkpoint — verified exact kernel config; runtime-feasibility decision

Owner ran the existing host-only review at commit `d820195`.
The original authenticated static LinuxLoader handoff showed:
`KernelEntry = KernelBaseAddr + imageFormatBias + (KASLRState << 15)`
or `KernelEntry = (BaseMemory | OEMImageFormatOffset) +
(KASLRState << 15)`. The `0x40` KASLR initializer is a **sentinel**,
not a measured runtime displacement. Neither the selected branch,
per-boot RAM base, actual DTB nor physical target was observed.

There are already TWO local, retained, read-only ADB reports:
`live-adb/20261010T130008Z/live-boot-evidence.md`
and `live-adb/20261010T130021Z/live-boot-evidence.md`.
**Read them, but do not reissue blocked/restricted device probes.**

Owner's current exact `config.gz` confirms:

| Option | Owner observed | Gate |
|---|---|---|
| `CONFIG_FUTEX_PI` | `y` | Subsystem built in; exploitability **not** proved |
| `CONFIG_RT_MUTEXES` | `y` | Source/code consistency |
| `CONFIG_DEBUG_RT_MUTEXES` | **not set** | Non-debug waiter struct selected; conditional debug fields absent |
| `CONFIG_MODULES` | `y` | Module framework built |
| `CONFIG_MODULE_SIG_FORCE` | `y` | Normal untrusted module insertion denied |
| `CONFIG_KPROBES` | **not set** | Existing KernelSU kprobe/kretprobe path unavailable |

The non-debug waiter priority candidate at offset `0x40`
in original `remove_waiter` is now additionally supported by the
configuration: two `struct rb_node` fields, task and lock pointers,
then `prio`. This **does not** establish a complete factory ABI.

**Focused next host-only action: summarize only *existing*
runtime observation statuses** without dumping private bootargs,
addresses or repeating ADB requests:

```bash
cd ~/src/Root-My-Galaxy-Payloads
python3 - <<'PY'
import json
from pathlib import Path
base=Path.home()/"s20-artifacts/hxl1-research/live-adb"
for path in sorted(base.glob("*/live-boot-evidence.json")):
    report=json.loads(path.read_text())
    print("REPORT",path.parent.name)
    print("  iomem:",report.get("iomem",{}).get("status","UNAVAILABLE"))
    props=report.get("bootProperties",{})
    for field in ("ro.boot.dtb_idx","ro.boot.dtbo_idx"):
        print(" ",field+":",props.get(field,"[UNAVAILABLE]"))
    for field in ("proc_cmdline","proc_bootconfig","proc_iomem",
                  "proc_dt_bootargs","sys_dt_bootargs","proc_dt_model",
                  "sys_dt_model"):
        print(" ",field+":",
              report.get("fileObservations",{}).get(field,{}).get("status",
              "NOT_COLLECTED"))
    for flag in ("physicalKernelEntryVerified",
                 "runtimeKaslrMeasured",
                 "runningDtbMatchedToBootloaderSelection"):
        print(" ",flag+":",report.get(flag,"NOT_COLLECTED"))
PY
```

**Acceptance criteria:** If the past device observations contain a
grounded DTB index, check against existing FDT candidate records;
otherwise document that specific limitation. An absent/restricted
IOMEM or bootargs never licenses guessing the physical address or
forcing access. ADB unprivileged shell cannot establish UEFI
KernelBaseAddr/KASLR independently on this evidence alone.

**Primary go/no-go:** With the locked bootloader, forced module
signatures and no kernel probes, the exact-device native/KernelSU
path is **BLOCKED** until a demonstrable authorized kernel-code
execution mechanism and compatible hook backend are available.
No stock source resemblance, linker symbol or futex-PI smoke test
alone satisfies this. Do not produce/flash an HXL1 module or
declare the profile supported.

**Engineering priority:** Obtain *new evidence* of an authorized
privileged loading route or a safely demonstrated HXL1-specific
runtime bug in an isolated reproduction. Until then preserve
the research profile and do not run another broad static scan.


## October 11 checkpoint — exact reported DTB/DTBO indices

The owner inspected *two already-retained* HXL1 device ADB records
(`20261010T130008Z` and `20261010T130021Z`, just 13 seconds apart).
Both give:

- `ro.boot.dtb_idx=0` and `ro.boot.dtbo_idx=2`;
- `/proc/cmdline`, `/proc/iomem`, both device-tree root
  `model` and `chosen/bootargs` interfaces: **PERMISSION_DENIED**;
- `/proc/bootconfig`: **NOT_PRESENT**;
- no verified physical Linux kernel load/entry, runtime
  KASLR or effective DTB hash.

These are two observations, **not independent boot measurements**.

The *offline* embedded stock boot-v2 region has four validated
contiguous FDTs in **one-based report order**:
candidate 1 Kona v2.1 at offset `0x0`,
candidate 2 Kona v2 at `0x81088`,
candidate 3 Kona v1 at `0x10210c`,
candidate 4 minimal 173-byte tree at `0x181c46`.
Its first bytes are FDT magic, **not** Android DT-table magic.
The selector's index base and its mapping to these four bytes
are **not independently established**. Therefore the observed
`dtb_idx=0` does NOT certify that first candidate is running.
The observed `dtbo_idx=2` is in a distinct *overlay* selection
domain, **not** candidate 3 of the four embedded base FDTs.

**Completed (owner WSL2):** No `dtbo.img`, `dtbo.img.lz4`
or `dtbo.bin` was found within five subdirectory levels under
`~/s20-artifacts`. The four original base FDT identities remain
unchanged. Record
`HXL1_ORIGINAL_DTBO_TABLE_NOT_IN_LOCAL_EVIDENCE`, not
`NO_DTBO_PARTITION_EXISTS`.
The `dtb_idx=0` and `dtbo_idx=2` properties are preserved
as bootloader selection hints only. No DTBO index or effective
tree hash is independently proven.

**Stop repeating the firmware/DTB and restricted ADB loops.**
A separate DTBO extraction or older Samsung FUS metadata lookup
should be reopened only if a concrete implementation or recovery
gate actually requires that evidence.

### Next consequential engineering milestone — isolated runtime feasibility

The original HXL1 `remove_waiter` bug-pattern, its stock
compiled access paths, selected struct member candidates and
six call destinations are documented. The pre-existing ARM64
QEMU lab booted **upstream** Linux 4.19.325 with debugging,
but did **not** reproduce the OEM HXL1 proxy-lock rollback
behavior, and did **not** match the device's complete Samsung
kernel or security policy. The target kernel is
`4.19.113-27095354`, not upstream 4.19.325.

Any further work must use a **safe, isolated, source-exact
regression** that distinguishes the potentially incorrect
`current`/waiter task cleanup branch from its patched
counterpart. It should measure only bounded state/lock
integrity in a disposable instrumented guest, not induce
unstable futex races on the real phone. First verify the
lab's actual source and configuration fidelity; if
HXL1 code cannot run there faithfully, treat reproduction
as `NOT_TESTED` rather than transferring upstream
results to the stock handset.

A demonstrated **cleanup bug is not automatically an exploitable
kernel read/write primitive**. A demonstrated primitive would
still not give KernelSU installation automatically.
The live `SM-G986U1` remains verified-boot locked with
`CONFIG_MODULE_SIG_FORCE=y` and
`CONFIG_KPROBES=n`; an independently verified
privileged code-loading route and a compatible Linux 4.19
hook/backend design remain absent. No root/profile release
until these are established.

**Current readiness:** Stages 1–2 COMPLETE, Stage 3 PARTIAL,
Stages 4–6 OPEN, Stages 7–8 BLOCKED, Stage 9 DEFERRED.
