# HXL1 select header macro provenance — next evidence gate (2026-10-14)

## Current original evidence

The owner supplied original Samsung source archives and the previous original-image-derived five-function AArch64 disassemblies. The prior checkpoint established source-level futex waiter/queue and native/compat select allocation lifetimes. These are **not** OEM-compiled C-local stack coordinates.

`fs/select.c` includes `<linux/poll.h>` and declares `long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];`. The two uploaded source files **do not contain `include/linux/poll.h`**, so previous reports correctly stopped short of claiming the exact HXL1 macro value. Standard Linux 4.19 `include/linux/poll.h` normally uses `#define FRONTEND_STACK_ALLOC 256` followed by `#define SELECT_STACK_ALLOC FRONTEND_STACK_ALLOC`; this is an **upstream reference**, not a substitute for Samsung HXL1 source attestation.

Upstream reference: https://lists.openwall.net/linux-kernel/2020/01/16/3121

The original HXL1 `core_sys_select` disassembly archive contains separately verified SP-relative local-buffer selection (`add x19, sp, #0x50`) and a size-dependent choice (`cmp x8, #0x180`). Both are represented in the existing SHA-checked saved disassembly. They support a source/compiled allocation-path crosswalk but do **not** establish C-variable offset semantics or any futex stack-memory reuse.

## New automation

`tools/y2q_hxl1_select_header_provenance.py` authenticates exact local sibling files `kernel/futex.c` and `fs/select.c` against previously recorded SHA-256 values, requires `fs/select.c` to include `linux/poll.h`, hashes the exact local `include/linux/poll.h`, follows the `SELECT_STACK_ALLOC` object-like macro alias chain, rejects ambiguity on that chain, and optionally rechecks the five preserved disassembly text digests and original select code-pattern anchors.

It **does not** invoke a compiler, preprocess a complete configuration, change firmware, contact ADB, deploy a kernel module, or produce exploit offsets. If the macro is a complex expression or conditionally redefined, the checker fails rather than guessing.

A single owner-side run, without another disassembly extraction:

```sh
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_select_header_provenance
python3 tools/y2q_hxl1_select_header_provenance.py \
  --source "$HOME/src/samsung-y2q-hxl1-stock" \
  --disassembly-archive "$HOME/s20-artifacts/hxl1-research/hxl1-disassembly-review.tar.gz" \
  --output "$HOME/s20-artifacts/hxl1-research/hxl1-select-header-provenance-20261014.json"
```

The JSON records all input hash identities and findings. Source macro result is **PENDING actual Samsung header** until this owner run succeeds. Do not claim that a public upstream macro value is HXL1 factory-proven.

## Remaining gates

- Exact HXL1 select header macro definition: **pending read-only owner checkout evidence**.
- OEM compiler configuration and C-local-to-machine-slot attribution: **not verified**.
- Runtime cross-syscall stack behavior and actual GhostLock exploitability: **not verified**.
- Temporary root and stock-signature-enforced KernelSU: **not achieved / blocked**.

Header provenance is a bounded next step, not a replacement for runtime evidence or an automatic promotion of the root readiness stage.
