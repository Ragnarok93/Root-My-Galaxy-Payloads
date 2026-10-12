# HXL1 — RKP sparse-bitmap pool boundary for Samsung QEMU (2026-10-11)

**Status:** Host-side C component implemented, tests committed but owner/CI execution not yet verified. **Not integrated into QEMU; no kernel boot or root claim.**

## Owner 15:44 UTC model gate

The owner ran `python3 -m unittest -v tools.test_y2q_hxl1_rkp_pool_model` after pulling branch commit `2bd6696`. All **7/7 tests passed**, including actual host-native C compilation, reservation containment, two-unit 1 GiB sparse boundary mapping, allocation and double-free behavior, out-of-range and oversized input guards, and checks that the component does **not** call QEMU guest-write APIs. **This is a confirmed successful synthetic component gate**, not a source-faithful RKP response, reserved DTB memory, usable guest descriptor or actual QEMU kernel boot. All fixture physical addresses are fictional and must not be treated as a selected HXL1 carveout.

## Verified inputs, origin, and limits

On the original SM-G986U1 G986U1UESCHXL1 factory Image (SHA256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`), the user executed an ARM64 guest with a physical guest breakpoint at the stock `SMC #0` instruction `0xffffff80080a5794`. The guest registers were `X0=0xc300c002`, `X1=0x15`, `X2=0xffffff800a4dd0b8`, `X3=0x40000000`, `X4=X5=0` and `X6=0x3f`. Their exact retained HXL1 Samsung source audit matched **RKP_GET_RKP_GET_BUFFER_BITMAP**, and the recovered `rkp_s_bitmap_buffer` symbol equaled X2. They subsequently ran `tools/y2q_hxl1_rkp_bitmap_preflight.py`: **14/14 tests PASS, 14/14 exact-source witnesses PASS, 4 KiB kernel pages**, plus `[FORK] NOT READY; protected pool and descriptor reservation unimplemented`.

The **existing public Samsung production-kernel QEMU patch** dispatches that X0/X1 tuple incorrectly as `KDP_SET_NS_FLAGS`. Do not use its KDP guest write. Source agreement for the initial call does not establish the firmware/hypervisor's correct bitmap contents or full response protocol.

## Source-derived guest ABI: what *must* exist

The original `sparse_bitmap_for_kernel_t` fields in `include/linux/rkp.h` are `u64 start_addr`, `u64 end_addr`, `u64 maxn`, `char **map`. In the intended 64-bit LP64 guest ABI this occupies **32 bytes**: each field and pointer is 8 bytes. This is a **layout expectation**, not a measured guest physical descriptor.

Original source reads the bitmap as follows:

1. Calculate `offset = pa - start_addr`.
2. Select 1 GiB unit `offset >> 30`; ensure it lies within `maxn`.
3. Select bit from `map[unit]` at page index `(offset % (1<<30)) / PAGE_SIZE`.
4. Follow original source fallback return values for a missing, out-of-range or uninitialized bitmap; do not invent behavior.

At **4 KiB PAGE_SIZE**, one 1 GiB unit requires `2^30 / (4096*8) = 32,768 bytes` of bit storage, plus an 8-byte guest pointer in the `char **map` array. For a hypothetical continuous **2 GiB** guest RAM layout, the source layout would use **two** such arrays (64 KiB total) and 16 bytes of pointer entries. This is a *format calculation*, **not a proposal for any specific HXL1 physical carveout**.

`rkp_robuffer_init()` appears in `paging_init()` before `map_kernel()` and `map_mem()`. Later source invokes `RKP_GET_RO_BITMAP=0x13`, `RKP_GET_DBL_BITMAP=0x14`, `RKP_START=0x01`, and the protected allocator/free calls `RKP_RKP_ROBUFFER_ALLOC=0x11` and `RKP_RKP_ROBUFFER_FREE=0x12`. At least these commands must be reviewed for actual HXL1 semantics and memory ownership before proclaiming the system initialized.

## QEMU-neutral C component — already committed

- `tools/hxl1_rkp_pool_model.h`
- `tools/hxl1_rkp_pool_model.c`
- `tools/hxl1_rkp_pool_model_test.c`
- `tools/test_y2q_hxl1_rkp_pool_model.py`

This **host-only prototype** provides (1) physically aligned, bounded RAM/reservation/pool range checks; (2) a source-consistent sparse owned-page bitset indexed relative to guest RAM start; (3) a **separate** allocator occupancy bitset, which rejects double-free, invalid free and exhaustion; (4) an API to retrieve host bitmap bytes and source-level descriptor field values.

The ownership-bitmap bit convention **1=page in RKP-protected pool** is an *explicit model hypothesis*, not a measured hypervisor output. Its membership is static even when an allocated page is freed, and no claim is made that the firmware's real buffer bitmap encodes exactly this occupancy. The C model receives an `external_reservation` argument as a **fixture contract**: that argument does not reserve any real QEMU guest memory or prove the reservation exists. The component contains **no** QEMU includes, `cpu_physical_memory_write`, Samsung UH SMC dispatcher, guest VA translation, or guest `char **map` pointer generation.

The tests compile a native C executable and check pool rejection outside reservation, sparse boundary correctness, allocator exhaustion/reuse, double-free and malicious ranges. Test execution status remains **UNVERIFIED** until owner WSL or CI runs these additions.

### Build/test command

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_rkp_pool_model
```

## 15:44 UTC — 7/7 C-model tests and guest descriptor staging

The owner pulled commit `2bd6696` and executed `python3 -m unittest -v tools.test_y2q_hxl1_rkp_pool_model`: **7/7 PASS**, including native C compilation with `-Werror`. This verifies **synthetic model behavior**, not firmware response or QEMU guest allocation. The model bit convention (1=protected-pool membership), pool-address fixtures, and free/allocated tracking remain *host hypotheses*.

### Added next source-derived component: fail-closed, guest-pointer staging

Committed `tools/hxl1_rkp_guest_stage.{h,c}`, `tools/hxl1_rkp_guest_stage_test.c`, and `tools/test_y2q_hxl1_rkp_guest_stage.py`. This QEMU-neutral serializer is the next narrowly reusable component. It accepts the existing host pool model and an **explicit set of four guest VA/PA mappings** (the observed original kernel global `X2` slot, 32-byte bitmap descriptor, `maxn*8` pointer table, and `maxn*32768` bit arrays). No virtual or physical address is guessed. Its caller must supply a **mandatory verify_mapping callback** that checks each claimed guest VA→PA mapping and writable backing; tests use a fictional map, whereas a future QEMU adapter must check the *actual* page tables and guest physical address space.

The implementation rejects:
- missing callback and failed mapping verification;
- 8-byte alignment, overflow, and incorrect buffer lengths;
- descriptor/table/bitmap regions outside the **externally reserved** physical range;
- descriptor/table/bitmap overlap with the protected pool or each other;
- global kernel pointer slot `X2` inside the external reservation, and VA aliasing.

On a validated synthetic mapping, it creates **host-only** serialized little-endian data: `global_pointer[8]` points at descriptor VA; `descriptor[32]` contains start/end/maxn/map VA; the pointer table contains bitmap unit VAs; and copied bitmap host bytes contain the source-consistent 1GiB sparse-unit format. The host serializer does **not** invoke `address_space_write`, construct a QEMU DTB, reserve real QEMU RAM, inspect guest translation tables, or commit a single guest byte.

**Six Python/unittest fixtures** compile the separate staging C program and test serialization, mapping rejection, non-overlap, bounded inputs, and memory lifetime. They were committed and enrolled in isolated CI, but **their WSL/CI execution has not yet been observed**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_rkp_pool_model \
  tools.test_y2q_hxl1_rkp_guest_stage
```

**Critical next adapter design:** QEMU must first reserve an HXL1-suitable real physical range *outside the kernel, device-tree, initrd and existing vendor carveouts*, expose a verified mapped VA to the bitmap descriptor and pointers, populate descriptor/bitmap physical memory before updating the **original** `rkp_s_bitmap_buffer` global `X2`, and implement failure/rollback semantics if any write fails. The source ABI tells us WHAT the kernel expects, not WHERE to place the backing memory. Do **not** hardcode the test's fictional `0x60000000` staging-region physical address, the fork's `0xa7000000` pool, or the synthetic `0xffffff800b000000` VA values.

### Expected future integration boundary

```text
Original G986U1UESCHXL1 Image / SHA pin
             |
    SMC X0=c300c002, X1=15, X2=original symbol VA
             |
    HXL1-gated UH dispatcher (NOT YET IMPLEMENTED)
             |
    VM-specific VA-to-PA and reserved memory verifier (NOT IMPLEMENTED)
             |
    host staging buffers (IMPLEMENTED / owner test PENDING)
             |
    QEMU guest writes with checks + rollback (NOT IMPLEMENTED)
             |
    source-faithful bitmap pointer/desc + later RKP cmds (NOT IMPLEMENTED)
```

This architecture deliberately does not confuse an isolated host test with proof of real guest memory or UH protocol correctness.

---

## 22:00 UTC — 13/13 owner regression pass and new transactional writer

The owner pulled the existing feature branch and executed both host-native suites:

```text
tools.test_y2q_hxl1_rkp_pool_model         7/7 PASS
tools.test_y2q_hxl1_rkp_guest_stage        6/6 PASS
Total                                       13/13 PASS
```

This verifies memory-pool accounting, sparse bitmap serialization, fail-closed **synthetic** VA/PA mapping checks, and host buffer lifecycle. **No actual QEMU RAM reservation, original UH output or Linux boot is established.**

**New code committed after this owner-verified gate:**

- `tools/hxl1_rkp_guest_commit.{h,c}` provides a **pluggable transaction** combining the validated guest descriptor staging with strictly ordered physical-memory operations. The caller must attest *all vCPUs stopped* and *external RAM reservation actually verified*, supply an MMU-aware VA→PA verification callback and trustworthy physical read/write operations.
- Its operations are: snapshot original bytes of all four regions, demand an initially NULL `rkp_s_bitmap_buffer` pointer slot and otherwise zero reserved backing, write bitmap bits then pointer table then 32-byte descriptor, verify each readback, finally publish and verify the original kernel global pointer. On failure, attempt reverse-order restore **including a partially written failing region**, compare restored bytes, and return `ROLLBACK_FAILED` if guest state cannot be trusted. Explicitly indicate when the original pointer slot may remain partially published.
- `tools/hxl1_rkp_guest_commit_test.c` and `tools/test_y2q_hxl1_rkp_guest_commit.py` test success, write ordering, partial writes, rollback failures, dirty memory, changing maps, readback corruption, paused/reserved preconditions, and uncertain pointer publication using a fictional four-region sparse RAM backend. **Nine new test functions** are committed and integrated into HXL1 CI. They **all passed** in GitHub Actions run `38179184038` (commit `d8dac2e`), along with the rest of the 135-test isolated workflow. The owner's separate WSL run of this new nine-test suite is still pending.

**CI-specific finding:** The latest CI run compiled and executed the initial eight new commit tests successfully, but the overall existing workflow was **red due solely to two previously existing AArch64 C-fragment tests**, which could not find `bits/libc-header-start.h`. The workflow was updated to install `libc6-dev-arm64-cross` with the previously installed AArch64 cross GCC and QEMU user-mode tools. The dependency correction was verified: [GitHub Actions run 38179184038](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38179184038) completed **SUCCESS**, with **135 tests OK** and no skips/errors in the unit-test run. This is CI-only coverage of host/source-fixture models, NOT a verified factory kernel guest boot.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v \
  tools.test_y2q_hxl1_rkp_pool_model \
  tools.test_y2q_hxl1_rkp_guest_stage \
  tools.test_y2q_hxl1_rkp_guest_commit
```

**Still not integrated into the emulator.** Passing a `ram_reservation_verified=true` flag in host fixtures is *not proof of reserved guest memory*. The next QEMU-specific work must inspect the actual `virt` DTB and physical address layout; implement a reserved-memory carveout outside the kernel/FDT/initrd, check mapped guest VA and physical backing using guest MMU state, and supply a correctly halted vCPU context. Only then can QEMU call the transaction and handle `X0=0xc300c002, X1=0x15`. Never dispatch it to the upstream fork's incompatible KDP handler. No physical-device code execution, unlock or KernelSU has been established.

---

## 22:13 UTC — transaction confirmed on owner WSL; QEMU virt DTB inventory gate

Owner pulled the transaction code and ran `tools.test_y2q_hxl1_rkp_guest_commit`: **9/9 PASS on WSL**. This independently confirms GitHub Actions' earlier **135/135 PASS** host+fixture run, including the guarded original-pointer publication and deliberately injected rollback failure. All three native C groups (pool 7, staging 6, transaction 9) are now owner-validated. These are tests with **fictional backend memory**, not QEMU device-memory operations or a working HXL1 virtual hypervisor.

**Next first-hand evidence gate now committed:** `tools/run_y2q_hxl1_qemu_virt_dtb_capture.sh` and `tools/y2q_hxl1_qemu_virt_dtb_inventory.py`. The former SHA-verifies the actual owner original `kernel.bin`, refuses existing output, and invokes **stock QEMU with the exact earlier SMC debugger machine profile** `virt,gic-version=3`, Cortex-A57, 1 vCPU, 2048 MiB RAM, with `dumpdtb=` and `-S` rather than running Linux. The inventory parses the generated binary FDT **without dtc**, reading the authoritative root memory `reg`, DT header memreserve entries, `/reserved-memory` fixed and dynamic properties, and `/chosen` initrd pointers; all are recorded as *inventory data*, not safe free pages. All **11 synthetic/guard tests passed** in isolated GitHub Actions run [#38179715298](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38179715298), which completed **146/146 tests OK**. Owner WSL DTB capture remains pending.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_virt_dtb_inventory
bash tools/run_y2q_hxl1_qemu_virt_dtb_capture.sh
python3 tools/y2q_hxl1_qemu_virt_dtb_inventory.py
```

The saved output directory defaults to `~/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011`, with `qemu-virt.dtb`, `qemu-version.txt`, machine profile, console/error status and `qemu-virt-inventory.json`. **Do not retry the default directory if it exists:** pass a fresh output directory as the shell argument and correspondingly `--dtb`/`--output` to the parser. The dump must exit successfully; unsupported `dumpdtb` property is an **INCONCLUSIVE** diagnostic, not an indication the factory kernel failed.

**Important limitation:** QEMU `virt` documentation states that RAM starts at `0x40000000`, matching the earlier stock image translation address `0x40080000`. But a dynamically generated DTB itself does **not** prove the kernel physical footprint, placement of the FDT/initrd and stacks, EFI loader allocations, the Linux memblock reserve state or the presence of any secure UH pages. An apparently empty `/reserved-memory` is specifically **not permission** to select a pool in live guest RAM. The program explicitly sets `suitableProtectedPoolProven=false`, `guestLinuxMemblockReservationProven=false` and `kernelFdtInitrdOverlapExcluded=false`. Any actual reserved pool requires a separately validated QEMU machine configuration/DTB node plus guest observation of the reserve *before* `paging_init`, along with full guest VA/PA checks for the original `X2` target and four staged buffer regions.

---

## 22:21 UTC — actual generated QEMU virt device-tree evidence

Owner WSL results are now **11/11 DTB-inventory unit tests PASS**, `dumpdtb` success without guest instruction execution and a read-only parser report:

```text
[DTB SHA256] 85b032cbf12948982de81fcdb6854d12ee7861d9a8cb852b9b060526d3252f87
[MEMORY] /memory@40000000 0x40000000 0xc0000000
[RAM RESERVATION VERIFIED] NO
```

A real QEMU `virt,gic-version=3`, Cortex-A57, 2048 MiB RAM FDT therefore advertises **two gigabytes of RAM**, without any memreserve/`reserved-memory` entries in the captured generated tree. **There is no verified protected RKP pool**. An empty reservation list is NOT evidence that an address is unused after the kernel, bootloader, FDT, page tables, memblock and runtime allocations.

A new SHA-pinned source correlation tool `tools/y2q_hxl1_qemu_boot_memory_audit.py` compares the original OEM `kernel.bin` size/ARM64 `image_size` header to the **exact** generated DTB SHA above, and cross-checks its FDT inventory JSON so no alternate guest profile can silently substitute for evidence. It treats trace-correlated low guest PC `0x40080000` as a **possible** load address, not a verified complete Image/BSS physical extent. It reports known DTB reservations, FDT `/chosen` initrd, and missing runtime placement evidence, and never auto-selects or carves a guest region. Fifteen isolated tests are committed in CI; their owner pass and audit result are **pending**.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_boot_memory_audit
python3 tools/y2q_hxl1_qemu_boot_memory_audit.py
```

Report: `~/s20-artifacts/hxl1-research/qemu-virt-dtb-20261011/boot-memory-conflict-audit.json`. Even if the Image leaves apparently broad free space, it is **not proof** that any carveout is reserved. Before the transactional stage can become a real `UH_APP_RKP` handler, the next tasks are to capture the exact boot-time FDT guest PA, install a verified memory reserve before Linux's memblock setup and validate MMU-aware guest VA→PA mapping and actual guest physical read/write.

---

## 22:26 UTC — original stock Image physical-span hypothesis and entry DTB capture

**Owner observed 15/15 boot-memory-audit unit tests PASS** and successfully ran the *actual* offline audit of their retained original SHA-pinned HXL1 Image, exact original QEMU generated `virt` DTB, and previously saved inventory. It confirms `2,147,483,648` physical bytes described in **`[0x40000000,0xc0000000)`**, with **zero FDT reservations**. Using trace-correlated candidate original Image PC `0x40080000` and max(original Image file size, ARM64 header image-size), the tool conservatively flags a **possible** Image span `[0x40080000,0x443bb000)`. This is **not an attested guest PA footprint**; it excludes neither guest boot loader allocations, BSS beyond that size, early page tables and stacks, nor runtime FDT and memblock reservations. The owner report is `qemu-virt-dtb-20261011/boot-memory-conflict-audit.json`.

The next committed step is **bounded original AArch64 boot handoff register capture**, not random carveout selection. New `tools/run_y2q_hxl1_qemu_entry_fdt_capture.sh` uses `-S` with localhost GDB and a hardware breakpoint at `0x40080000`; it reads `X0-X3` and only 16 guest bytes from `X0` without modifying the stock guest. AArch64 Linux boot protocol specifies **X0 = physical DTB pointer**, **X1-X3 = zero** when entering the primary kernel. `tools/y2q_hxl1_qemu_entry_fdt_audit.py` checks original Image/DTB hashes, actual `PC`, `X0` 16-byte FDT magic/size, RAM containment and candidate Image overlap, and refuses to claim a full guest FDT dump or protected-memory pool from a header alone. The initial **17 regression tests passed in GitHub Actions run #38180648987 (178/178 suite)**. The 18th declared-FDT SHA/file-padding test also **passed**. The updated [GitHub Actions run #38180778127](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38180778127) is **green (179/179 tests, 18 entry/FDT tests)**. The owner GDB entry capture remains pending. The owner has not yet run this GDB entry capture.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_entry_fdt_audit
bash tools/run_y2q_hxl1_qemu_entry_fdt_capture.sh
python3 tools/y2q_hxl1_qemu_entry_fdt_audit.py
```

Saved to `qemu-entry-fdt-20261011/gdb-session.log` and `entry-fdt-audit.json`. Actual FDT PA and eventually its full bytes are prerequisites for a safe pre-Linux reservation; **the FDT header alone never grants authority to set `ram_reservation_verified` to true** in the host transaction model. Until a private QEMU adapter actually reserves and maps guest memory and the original guest confirms its memblock state, the exact HXL1 RKP descriptor/bitmap remains a tested *host-only* implementation. Root/KernelSU/bootloader unlock remain separate blocked milestones.

---

## 22:34 UTC — runtime FDT entry physical address and full-DTB preservation gate

The owner has now measured a **real original HXL1 guest-entry register state** on the proven generic QEMU `virt` profile, independent of the QEMU `dumpdtb` file:

```text
PC 0x40080000
X0 0x48000000 — valid boot FDT magic and total_size 0x00100000
X1 0x0, X2 0x0, X3 0x0
FDT guest physical [0x48000000,0x48100000), 1,048,576 bytes
Overlap with previous original-Image candidate [0x40080000,0x443bb000): None
```

All **18 entry-source tests passed** on the owner's WSL. At this stage the **first sixteen header bytes only** have been read in full from guest memory. The earlier generated `virt` FDT had no explicit memory reservations, but the actual runtime FDT's complete `/reserved-memory`, memreserve and `/chosen` content has **not yet been read**. A valid header and no Image overlap do not establish a safe RKP guest physical pool.

**New code committed:** `tools/run_y2q_hxl1_qemu_runtime_fdt_capture.sh` performs a new **read-only** bounded (`60s`) localhost QEMU/GDB session at the original entry, checks guest `PC=0x40080000` and `X0=0x48000000`, and uses GDB's binary guest-memory dump to record the complete `1 MiB` FDT without changing guest state. `tools/y2q_hxl1_qemu_runtime_fdt_compare.py` independently validates the earlier source-report, original generated FDT hash, old and new GDB header bytes, full runtime DTB structure, memory `reg` and reservation semantics. It reports byte-level and semantic differences, without demanding that two FDTs necessarily have the same hash. **All 16 synthetic tests passed** in [GitHub Actions run #38181271133](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38181271133), with **195/195 full-suite tests OK**. The real 1 MiB runtime DTB has not yet been collected on the owner's WSL.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_runtime_fdt_compare
bash tools/run_y2q_hxl1_qemu_runtime_fdt_capture.sh
python3 tools/y2q_hxl1_qemu_runtime_fdt_compare.py
```

Artifacts will be in `qemu-runtime-fdt-20261011`. GDB failure or a partial binary capture is **INCONCLUSIVE** and the attempt's evidence directory must be retained unmodified. The next QEMU implementation decision requires **actual reserved-memory plus Linux memblock page exclusion**, not merely a FDT node or proposed gap. No SMC handler or guest write is implemented.

---

## 22:46 UTC — original guest full FDT is unreserved; first diagnostic -dtb canary

Owner WSL confirmed the complete read-only 1 MiB original kernel-entry FDT guest memory dump using `tools/run_y2q_hxl1_qemu_runtime_fdt_capture.sh`, and the `tools.test_y2q_hxl1_qemu_runtime_fdt_compare` **16/16 unit tests passed**. Its guest FDT SHA-256 is `e842cd6cc6b7fc391420bd571dd0f9af3aec7f223101367ddcf14853bd3a7814`, at `[0x48000000,0x48100000)`. The raw FDT differs from generated `dumpdtb`, yet the **limited** semantic inventory shows zero reported differences, **0 runtime memreserve entries** and **0 runtime `/reserved-memory` regions**. There is no verified RKP physical reservation. The statement is now backed by actual kernel-entry guest memory, not just an offline generated device-tree file.

**Next implementation is a harmless canary, NOT a protected-pool allocation.** The goal is to test whether an original-image QEMU `-dtb` override can carry an explicitly constructed FDT memreserve entry through the Linux handoff. A new `tools/y2q_hxl1_qemu_fdt_canary.py` creates a separate byte-exact-preserving FDT copy with only one reserve-map entry for the **already-in-use** FDT pages `[0x48000000,0x48100000)`; it does not reserve a new free page, allocate an RKP buffer or select a carveout. A second local-QEMU GDB script captures the resulting full guest FDT with a bound original `PC=0x40080000`, `X0=0x48000000`; an independent verifier refuses a missing or unexpected entry, changed RAM profile, wrong guest header or evidence mismatch. See [QEMU FDT self-reservation canary research](SM-G986U1-HXL1-QEMU-FDT-MEMRESERVE-CANARY-20261011.md).

The exact **17 fixture tests passed** in [Actions run #38182029643](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38182029643) with **212/212 suite PASS**. The owner's live QEMU `-dtb` delivery evidence is still **PENDING**; success in CI cannot substitute for it. Even after an actual guest FDT memreserve delivery PASS, `ram_reservation_verified` for the protected pool **must remain FALSE** until guest Linux memblock or a stronger runtime-independent allocator-exclusion proof exists. The unrelated physical-phone unlock and KernelSU paths remain unproven.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_qemu_fdt_canary
python3 tools/y2q_hxl1_qemu_fdt_canary.py
bash tools/run_y2q_hxl1_qemu_fdt_canary_capture.sh
python3 tools/y2q_hxl1_qemu_fdt_canary_verify.py
```

---

## 22:53 UTC — FDT reservation canary bounded-length correction

Owner-ran original `-dtb` canary test succeeded at the **synthetic** 17/17 unit gate and produced a local QEMU/GDB dump, but the offline verifier stopped at `Invalid declared DTB size`. This is a **truncation bug in the first canary capture**, not an HXL1 original-kernel boot failure: the canary adds 16 bytes of FDT memreserve data to the source's full 1 MiB FDT, while the old GDB dumper read only 1 MiB. The corrected code measures the actual guest header `totalsize` dynamically, verifies captured length and GDB marker, and sets the canary to reserve the entire augmented FDT rounded to 4 KiB, i.e. `[0x48000000,0x48101000)` for a 1 MiB original DTB. The original evidence must remain immutable.

The corrected **23 canary synthetic tests and full 218-test isolated workflow passed** in [Actions run #38182473039](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38182473039). The owner has **not yet completed the v2 guest delivery verification**, and even a future positive memreserve delivery is not proof of Linux memblock allocator exclusion or any secure RKP pool. [Precise v2 procedure](SM-G986U1-HXL1-QEMU-FDT-MEMRESERVE-CANARY-20261011.md#2253-utc--owner-guest-dump-exposed-fixed-length-truncation-corrected-canary-v2).

---

## 23:57 UTC — QEMU delivered canary memreserve; no secure pool or allocator exclusion

Owner v2 full guest FDT capture conclusively measured **2,117,184 (0x204e40) bytes** at the original `X0=0x48000000` after supplying a QEMU `-dtb` override. The verifier's only failure was **`Canary does not cover the complete page-rounded FDT`**, after all prior provenance, GDB header, exact full capture, guest RAM profile, and guest memreserve equality checks succeeded. Thus the diagnostic `[0x48000000,0x48101000)` memreserve **reached the guest**, but it did **not** reserve enough bytes for the expanded `[0x48000000,0x48204e40)` runtime FDT. The observed minimum page-rounded *FDT self-reservation* is **`[0x48000000,0x48205000)`**, 2,117,632 bytes. This is **not evidence of a new free protected pool**. In particular, QEMU `-dtb` delivery changes the device tree but has not been verified to change Linux 4.19 memblock's recorded reserved regions or the physical secure UH allocation mechanisms.

`tools/y2q_hxl1_qemu_fdt_canary_verify.py --audit-delivery-only` separately reports `DELIVERED_BUT_SELF_RESERVATION_UNDERSIZED` against saved v2 evidence without rewriting the input or running guest code. The normal strict verifier still rejects insufficient coverage. `tools/y2q_hxl1_qemu_fdt_canary.py --self-reserve-bytes 2117632` builds an optional independently measured *v3 self-reservation diagnostic*, **not** an RKP pool. The offline source/CLI/capture tests are now **27/27 PASS**, and isolated GitHub Actions run [#38186388440](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38186388440) is **222/222 PASS**. The owner's forensic replay and v3 runtime GDB capture remain pending.

**Revised next integration gate:** Because `-dtb` memreserve delivery is now evidenced, stop treating transport as the primary blocker. Instead trace **exact original 4.19 HXL1 `early_init_fdt_scan_reserved_mem` / `early_init_dt_scan_reserved_mem` / `memblock_reserve`** control flow on the actual guest to prove the Linux allocator excludes the relevant pages before attempting any new RKP region. The exact symbol name/path on HXL1 must be verified from original stock kernel/source; these names are investigation candidates, **not proven available symbols**. Only after an actual nonoverlapping candidate plus early reserve and safe VA→PA mappings are proven can `hxl1_rkp_guest_commit` leave its current host-only test backend. Avoid guessing at secure-hypervisor ABI commands or copying fork-specific KDP handlers.

---

## October 12 — no original HXL1 memblock call observed after guest entry; fault PC unknown

Actual owner v2 GDB results verified **original kernel entry** with the QEMU v3 canary (entry `0x40080000`, FDT pointer `0x48000000`) but **timed out after entry** without a `memblock_reserve` or Samsung UH SMC breakpoint. The QEMU exception trace contained only `Invalid read at addr 0x3FFFFFFC, size 4, region '(null)', reason: rejected`, which is four bytes below the `virt` DRAM base. The warning does **not** report the guest CPU PC or FAR/ESR at access time and cannot be attributed to a specific stock original-image instruction. A patched `memblock_reserve` call is not warranted; allocator exclusion remains **unverified**.

The recovered candidate `memblock_reserve` address `0xffffff80082a0844` correlates with original `0xd10103ff`, but recovered `vmlinux-stock.nm` does not by itself prove the relevant call was executed or reached after entry. A new bounded, local-only QMP CPU snapshot experiment (`tools/y2q_hxl1_qemu_memblock_pc_sampler.py`) samples `info registers` via QMP over a private UNIX monitor socket, records exposed PC, ELR, FAR and ESR without modifying guest memory, and optionally contrasts verified v3 `-dtb` with factory QEMU-generated DTB (baseline). This requires original factory Image SHA and existing strict v3 canary evidence. Its host unit tests are isolated from QEMU execution. The new owner-run PC/exception snapshots are **pending**. It records `linuxMemblockAllocatorExclusionVerified=false` regardless of outcome.

Only if a stock instruction is demonstrably reached and its call output/source semantics independently checked should allocator-state tracking proceed; do not infer either success or failure from GDB timeout or identical sampled PCs alone.

---

## Required proof gates before a functional QEMU adapter

| Gate | Acceptance criterion | Present status |
|---|---|---|
| External reserve | Select HXL1-specific physical RAM location using actual available/reserved memory map, install `reserved-memory` DTB reservation or equivalent before Linux's buddy allocator starts, and independently verify no overlap with kernel/initrd/FDT | **NOT IMPLEMENTED** |
| Sparse descriptor | Allocate guest-visible 32-byte LP64 struct, guest VA pointer array and unit bit arrays with verifiable physical backing | **NOT IMPLEMENTED** |
| Guest translation | Use QEMU MMU-aware guest memory writes at validated virtual-to-physical addresses; verify guest can read descriptor and each `char **map` pointer after early page-table changes | **NOT IMPLEMENTED** |
| Initial RKP call | Exactly match HXL1 `X0=0xc300c002, X1=0x15`, handle pointer `X2`, guest RAM start `X3` and return values; do not trigger the upstream fork's KDP writer or fake success | **NOT IMPLEMENTED** |
| Protected allocation | Track actual guest-protected pool physical-page allocation/free and match `0x11/0x12` side effects; check the original HXL1 bitmap semantics against source reads and later guest execution | **HOST-ONLY FIXTURE** |
| Remaining calls | Source-verify `0x13/0x14/0x01` and any other observed firmware calls; report unsupported commands explicitly | **NOT IMPLEMENTED** |
| Kernel progression | Re-run **original SHA-pinned factory Image** in an isolated QEMU fork build, record GDB `X0…X6`, exception trace and actual *executed* blocks (`-d exec,int`) | **NOT RUN** |

**Do not** flash the real Galaxy S20+, patch the original Image, NOP SMC, import the upstream KDP handler, or turn unknown firmware calls into unconditional success. A bootable stock-firmware emulator would be important research progress but would still not provide a physical-phone kernel code injection route, bootloader unlock, KernelSU installation, or proof of an RTmutex vulnerability.
