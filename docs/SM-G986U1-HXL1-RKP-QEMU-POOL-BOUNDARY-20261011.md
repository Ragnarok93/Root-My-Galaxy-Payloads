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
