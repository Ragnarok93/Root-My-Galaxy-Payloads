# HXL1 Stage 3 — saved REA/Ghidra evidence bundle review (2026-10-13)

Reviewed the owner's original `HXL1-stage3-review-20261013T112229745070Z.zip` uploaded in this conversation. Inspection was read-only, using its original ZIP members (no extraction, execution, Ghidra rerun, payload, phone connection or kernel recompilation).

## Cross-file integrity and findings

- Ten manifest-listed ZIP members: **10/10 SHA-256 values verified**.
- Cross-file factory Image SHA256 **agrees**: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.
- Clang10-comparison candidate offsets vs Clang18 compiled Samsung-source DWARF: **13/13 numerical agreement**.
- **Original saved live REA/Ghidra report**: **9/13 static register chains matched**. Four `rt_mutex_waiter` fields (`task`, `lock`, `prio`, `deadline`) were *not in the original chain worklist*.
- **Retrospective recheck used by the newer Clang18 parity script**: **13/13 static chains matched**, because newer `tools/y2q_hxl1_stage3_member_flow.py` source adds chains for those four fields. This must **not** silently overwrite or relabel the immutable original result.
- **Factory-identified OEM C fields certified: 0/13**. Stage 3 remains **PARTIAL**, not a root-capable device profile.
- The ZIP contains neither the original complete stock `kernel.bin` nor Samsung source, so this inspection independently verifies ZIP SHA integrity and report **cross-consistency**, not the original factory-firmware byte pins again.

## Saved Ghidra High P-code

| Function | Native instructions | Retained P-code operations | Retained def/use links | Truncated | Known omitted links |
| --- | ---: | ---: | ---: | --- | ---: |
| `remove_waiter` | 140 | 214 | 215 | No | 0 |
| `rt_mutex_start_proxy_lock` | 38 | 21 | 15 | No | 0 |
| `futex_lock_pi` | 545 | 3,000 | 4,168 | **Yes** | **52** |

The `futex_lock_pi` decompiler body is reported as noncontiguous and contains warnings about bad instruction data/type propagation. Its exported P-code is explicitly incomplete. The other two have untruncated provider outputs, but the decompiler still lacks stock OEM C member types, memory-alias completeness and cross-function dataflow guarantees.

## Concrete false-positive risks in raw displacements

- `task_struct.pi_lock` at `+0x8c8` is present as a **computed address** (`add x21,x20,#0x8c8`, where `x20` came from `sp_el0`). A memory-operand-only scanner returns zero candidate sites, although the saved static register chain matches. Fix classification, not the stock offset.
- The `remove_waiter` load at `0x1013c` is `[x8,#0x18]`; if `x8` is the `pi_tree_entry` node inside a waiter (nested base offset `0x18`), the enclosing waiter task is at `0x18+0x18=0x30`. The immediate `0x18` alone is **not** an OEM field identity.
- The `remove_waiter` load at `0x101e4` uses `[x9,#0x30]`; if `x9` denotes the nested PI tree node, the effective enclosing waiter offset becomes `0x18+0x30=0x48` (candidate `deadline`), not the similarly numbered waiter `task`. This nesting interpretation still needs complete source / register def-use proof.
- Stack-relative accesses in the larger futex function share immediates with kernel members. **Never identify members from offset equality alone.**

## Correction in the canonical parity script

Commits `366ea126` and `c25990b` repair the audit semantics of `tools/y2q_hxl1_stage3_abi_crosscheck.py` and add regression cases. Reports now retain **both** `savedOriginalRegisterChainStatus` and `retrospectiveRecheckRegisterChainStatus`, including `originalMatchedStaticChains` and `retrospectiveMatchedStaticChains`. Original 9/13 cannot be silently converted to 13/13 by current-code rechecks.

Run on the owner WSL host, reusing the unchanged raw evidence and compiled objects:

```sh
cd ~/src/Root-My-Galaxy-Payloads && git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_stage3_abi_crosscheck
python3 tools/y2q_hxl1_stage3_abi_crosscheck.py
```

The script produces a **new** timestamped parity report without rerunning Clang, REA, Ghidra, QEMU, bootchain analysis or root code.

## Remaining work (not a numerical offset search)

Create member-specific original-source bindings through authenticated register/branch paths and nested `container_of` transformations, especially for the four retrospectively added candidates. Use retained complete Ghidra P-code for the smaller two functions; scope a future bounded `futex_lock_pi` query to only missing sites if required, and do not infer missing edges from a truncated export.

Stage 1–2 COMPLETE; Stage 3 PARTIAL; Stage 4–6 OPEN; Stage 7–8 BLOCKED; Stage 9 DEFERRED. No GhostLock runtime primitive, phone root, KernelSU installation, bootloader unlocking or physical firmware modification is demonstrated by the uploaded archive.
