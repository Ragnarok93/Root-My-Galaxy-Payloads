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
