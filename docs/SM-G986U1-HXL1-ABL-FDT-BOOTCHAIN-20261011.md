# SM-G986U1 HXL1 LinuxLoader — FDT composition and boot-image handoff (static REA evidence)

**Date:** 2026-10-11. **Target:** Samsung SM-G986U1, `G986U1UESCHXL1`. **Scope:** offline read-only static analysis, not a working root procedure. **Original:** `~/s20-artifacts/hxl1-research/abl-linuxloader/LinuxLoader-HXL1.efi`. **SHA256:** `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`. All `0x...` function and string addresses below are Ghidra addresses for the analyzed PE image, **not** confirmed runtime physical addresses.

All full REA JSON reports remain on the owner's WSL under `~/s20-artifacts/hxl1-research/abl-linuxloader/rea-dt-index-LBaPQ6`; do not commit binary/large raw analysis artifacts or equate instruction evidence with a runtime measurement.

## Verified chain and exact scope

- `FUN_00020a60` owns base-DTB selector `BL 0x25108` at `0x21a78` and conditional board-DTBO selector `BL 0x263c8` at `0x21a9c`. `FUN_00023b80` reads the inverted low bit of a byte at `0x3460b40`, which base selection may set to 1.
- `FUN_00026f68` **appends**, not merges, input FDTs to a `0x18`-byte/node linked list: pointer `+0`, size `+8`, next `+0x10`. `FUN_00027040` releases list nodes and clears the head.
- `FUN_0004f418` receives the validated base FDT, size and input-list head at `0x21db4`, builds an output FDT and returns it in `x0`. `FUN_0004eab8` handles overlay fixups and tree/property modifications, `FUN_00054178` parses an FDT into an internal representation, and `FUN_00054378` serializes the result. Original PE strings include `/__local_fixups__` at `0xc6f3e`, `/__symbols__` at `0xc6f50`, `/__fixups__` at `0xc6f5d`, and `/` at `0xbf43f`.
- Shared owner `0x21e98` passes `x0 = [sp+0x78]` (destination), `x1 =` composed FDT pointer and `x2 =` endian-converted FDT `totalsize` to an indirect copy-like routine through service slot `+0x160`. Preceding `0x21e28–0x21e3c` checks that size against `[sp+0x70] - [sp+0x78]`. `FUN_00027ea8` later receives the FDT destination and boot parameters at `0x22304` and contains further FDT property work.
- Kernel entry candidate is in `[sp+0x60]`, destination FDT candidate in `[sp+0x78]`. Direct indirect transfers are `blr x8` at `0x22854` (FDT in `x0`) and `0x228a8` (FDT in `x2`); a separate firmware-mediated indirect call exists at `0x227d4`. These are **static candidate handoffs**, not live proof of a specific stock path, ARM execution-state transition, address translation, or boot success.

### PE constants (verified file-backed values)

`0xb2210 = 0x00080000`, `0xb2214 = 0x05600000`, `0xb2218 = 0x03c00000`, `0xb221c = 0x00008000`. The firmware selects one pair according to `sp+0xc0`: when zero, `entry = [sp+0x30] | 0x80000` and layout boundary `[sp+0x30] + 0x05600000`; when nonzero, `entry = [sp+0x30] | 0x8000` and boundary `[sp+0x30] + 0x03c00000`. Preserve the original `OR` (not an assumed addition). A distinct path derives entry/boundary from firmware-service outputs temporarily at `sp+0xd8`/`sp+0xe8`; both stack slots are later reused for other purposes. The boundary and FDT destination are calculated at `0x211c8–0x211e0`; no absolute runtime physical addresses have been measured.

## October 11 boot component and image-format findings — corrective identification

### `FUN_000228e0`: named component-table lookup, **not** a general boot-header parser

- Called at `0x20b9c` with `x0` pointing at loader input structure, `x1 = sp+0x38`, `x2 = sp+0x40`, `x3` naming the component. Original strings: `boot` at `0xc7f9d`, selected when `w21 == 0`; `recovery` at `0xbfffa`, otherwise.
- Table entry count `[x0+0x428]`. Each `0x18`-byte entry has a name pointer at `+0x128`, output field at `+0x130`, and second output field at `+0x138` (relative to input structure plus `0x18 * index`).
- `0x22944` calls a string-length helper and `0x22954` calls a comparison helper. Zero match goes to `0x229a8`, writes matching fields into `[x1]` and `[x2]` and returns zero. Bad arguments return `0x8000000000000002` (EFI_INVALID_PARAMETER); missing entry returns `0x800000000000000e` (EFI_NOT_FOUND).
- **Correction:** the function does **not** write `sp+0x30`. `FUN_0001f018` at caller `0x20d38` receives `x0 = sp+0x30` and is a next target for the source of the kernel-image base. Any output-parameter writes by other helpers must also be considered.

Evidence: `ev_db2f05a7ca63ef9bf582fef4cb84d113db13c749943c437bfa99668a1598faaa`; saved as `rea-instructions-boot-metadata-parser.json` (legacy filename: semantic role corrected above).

### `FUN_00023a78`: gzip signature check, **not** a kernel architecture classifier

The function returns true only if the pointer is non-null, supplied size is at least 10 bytes, and bytes `[0..2]` equal `1f 8b 08` (gzip magic and DEFLATE compression method). At caller `0x20ef0`, a true result sets `sp+0xc2 = 1`. Other flags are separate: `sp+0xc1` is set when a 16-byte comparison at `0x21038` matches, then the candidate pointer advances `0x14`; `sp+0xc0` is set if the ARM64 Image header signature `0x644d5241` is absent at `+0x38`. Do not confuse these three flags or label `FUN_00023a78` as an architecture classifier.

Evidence: `ev_fdb03f093cff8cdd8ce4e8db79d8081a5fac7ebac28457ff910d8320bd1ccfbf`; saved as `rea-instructions-kernel-image-classifier.json` (legacy filename: semantic role corrected above).

Shared owner's saved REA evidence: `ev_65699d02d3e20131f7204420e8baef7e80d6170f32030f65ae1fff6c98f16341`.

## October 11 follow-up — minimum memory-address selection and uncompressed wrapper

### `FUN_0001f018`: lowest-record-address selection (NOT boot-header parsing)

Called from `FUN_00020a60` at `0x20d38` with `x0 = sp+0x30`. `FUN_0001f018` calls `FUN_0001eca0` with addresses of a pointer and 32-bit count in its own stack frame; on the non-error path it traverses the returned array with **16-byte stride** and reads its first 64-bit field per record. The scalar tail at `0x1f12c–0x1f140` uses `cmp x8,x11; csel x8,x11,x8,hi`, so the **smaller unsigned value** is selected; the NEON reduction likewise selects the minimum, rather than the maximum. Final store is `0x1f144: str x8,[x20]` into caller's `sp+0x30`.

Therefore `sp+0x30` is best called the **selected minimum memory base/address**. Whether the records are DRAM banks, reserved memory extents or a different firmware memory map remains **unverified until `FUN_0001eca0` is classified**; do not call this a proven physical DRAM base or boot-header value. Zero-count/error corner cases have not been separately reconstructed.

Evidence: `ev_a5f35edeba6a91c3c67647f320d4f8ea58043ee34dfbfcb9e07f8ab7de28dd0c`, retained in `rea-instructions-image-metadata-0x1f018.json` (legacy label). The original HXL1 EFI SHA256 pin remains unchanged.

### The signature at `0xbcc59` is `UNCOMPRESSED_IMG`

The PE-mapped 16 ASCII bytes `55 4e 43 4f 4d 50 52 45 53 53 45 44 5f 49 4d 47` spell **`UNCOMPRESSED_IMG`**. At owner `0x21028–0x21048`, `FUN_0003be30` compares 16 bytes against this signature. On equality, the loader advances its candidate pointer by `0x14` (20 bytes) and sets `sp+0xc1 = 1`; the four bytes following the signature have not yet been classified. A separate comparison reads ARM64 magic `0x644d5241` at `image+0x38`; absence sets `sp+0xc0 = 1`. `sp+0xc2 = 1` is the separate gzip/DEFLATE signature result from `FUN_00023a78`. Do not collapse these flags.

### Next narrow evidence targets

1. Read `FUN_0001eca0` from the pinned ELF/PE original through REA/Ghidra instructions to classify the enumerated `0x10`-byte address records and the free/ownership lifetime; confirm the minimum-address interpretation against record layout.
2. From the cached caller, inspect how `sp+0x30` is used relative to `sp+0x38`/`sp+0x40`, and which path reaches `0x20d38`; if a matched offline boot payload is available, inspect the **payload bytes** at offsets `+0x10..+0x13` after a recognized `UNCOMPRESSED_IMG` marker. The bytes adjacent to the marker string **in LinuxLoader-HXL1.efi** are unrelated constant-storage context and must not be mistaken for payload bytes.
3. Preserve the separate run-time physical address, actual selected FDT and locked-bootloader/rootability gates; classify firmware-mediated `0x227d4` dispatch only after the memory-record semantics are grounded.

### `FUN_0001eca0`: Qualcomm EFI RAM-partition protocol — original GUID and ABI authenticated

New REA evidence `ev_e9e49405806db914b7e08b49c2f1a877473f1b9c05b0a4f0a64664ebcb71dd1d` (`rea-instructions-memory-record-provider-0x1eca0.json`, 146 instructions) establishes a cached protocol record provider:

- Cached pointer `[0x3460ad8]` and `UINT32` record count `[0x3460ae0]` returned through caller pointers `x0` and `x1` at `0x1ece0–0x1ece4`.
- If cache empty, `EFI_BOOT_SERVICES.LocateProtocol` at table offset `+0x140` is invoked for a 16-byte GUID constant at original-PE address `0xef880` (`0x1ed1c–0x1ed40`).
- On success, firmware method `[protocol+0x18]` is first invoked with null record buffer and pointer to count (`0x1ed58–0x1ed70`); the code expects `EFI_BUFFER_TOO_SMALL` (`0x8000000000000005`) by subtracting 9 from `EFI_NOT_FOUND` constant `0x800000000000000e`.
- It allocates `count << 4` bytes (16 bytes per record), caches allocation at `0x3460ad8`, then invokes the same protocol method with the allocated buffer and count pointer (`0x1ed80–0x1eda8`). Error handling includes zeroing/freing the cached allocation.
- **Source-and-binary authenticated identity:** Qualcomm `EFI_RAMPARTITION_PROTOCOL`'s `GetRamPartitions` method sits at offset `+0x18`, takes `(This, RamPartitionEntry* entries, UINT32* NumPartition)`, and reports `EFI_BUFFER_TOO_SMALL` on the sizing call. `RamPartitionEntry` is exactly 16 bytes: `UINT64 Base; UINT64 AvailableLength;`. Header: [Qualcomm EDK2-derived EFIRamPartition.h](https://github.com/SHIFTPHONES/android_bootable_bootloader_edk2/blob/sos-3.x/QcomModulePkg/Include/Protocol/EFIRamPartition.h).
- **GUID authentication complete (owner's pinned-original WSL run, 2026-10-11):** PE address `0xef880` mapped to `.text` file offset `0xef880`. Extracted 16 bytes `b5 ff 72 51 53 42 51 7d c6 41 a7 01 f9 73 10 3c` decode via UEFI mixed-endian GUID as **`5172ffb5-4253-7d51-c641-a701f973103c`**, exactly matching `EFI_RAMPARTITION_PROTOCOL_GUID`. The entire EFI was SHA256 verified before extraction. **Outcome: exact binary GUID match, plus the previously demonstrated method offset `+0x18`, 16-byte records and two-pass count retrieval.**
- The record first 64-bit value read by `FUN_0001f018` is now identified as `RamPartitionEntry.Base`; its minimum becomes `[sp+0x30]` in `FUN_00020a60`. `AvailableLength` is the second 64-bit member but is not consumed by this minimum calculation. No actual base, number of DRAM banks, final kernel physical address or live root permissions are inferred.

## Next bounded gates

1. DONE: inspected cached caller, identified `UNCOMPRESSED_IMG` at `0xbcc59` and authenticated the conditional `0x210cc`. DONE: HXL1 GUID at `0xef880` matched Qualcomm RAM-partition protocol exactly. The conditional `0x210cc: orr x8,x0,x24; cbz x8,0x21180` determines whether service-supplied layout outputs or constant-offset layout is selected.
2. DONE: classified `FUN_0001f018` as a **minimum-address reducer** and `FUN_0001eca0` as a cached EFI protocol record provider. Qualcomm `EFIRamPartition.h` ABI and original-HXL1 GUID are authenticated.
3. Authenticate `0x227d4` callback/dispatch provider and branch gating; distinguish the observed register arguments from an asserted ARM execution-state switch.
4. Compare offline candidate base FDT, overlays, and post-fixups with runtime-safe metadata if obtainable. There is no demonstrated bootloader unlock/root/KernelSU execution route. Keep the stock locked phone unchanged.

**Readiness statement:** Static firmware-to-FDT/entry chain is substantially mapped, but final booted FDT bytes, absolute runtime addresses, stock-branch selection, relevant security boundaries and actual root payload execution remain unverified. Do not promote this research-only work to a flashable or executable profile.
