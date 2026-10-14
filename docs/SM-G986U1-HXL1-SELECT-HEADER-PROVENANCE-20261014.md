## October 14 — updated numeric crosswalk returned and verified

Owner's `hxl1-select-numeric-crosswalk-20261014.json` (SHA-256 `f1c5114692a059ebc1c5d1542af19170640989054b998697c26ca0f7eb21a478`) confirms the **updated numeric verifier ran successfully**. The report records `compiledArithmeticMatchesSourceCapacity=true` and preserves all non-certification flags. Independent container review of previously uploaded `hxl1-source-dispatch-review.tar.gz` rehashed both source files and matched `kernel/futex.c` and `fs/select.c` to the report. An independent pass over the separately uploaded original disassembly archive matched its SHA (`20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997`), validated all five saved disassembly text SHA-256s, and counted 266 contiguous native `core_sys_select` instruction slots.

The native HXL1 source/binary arithmetic matches: **256-byte local `stack_fds` source capacity**, six native bitmaps using eight-byte longs, **five words per bitmap**, local storage through **320 descriptors**, first dynamic-allocation count **321**, allocation scaling **48 bytes per group of 64 descriptors**, and `cmp x8, #0x180` after rounding the count up by 63. Saved code also has the corresponding conditional branch into `add x19, sp, #0x50`, and `3 * group_count << 4` dynamic sizing.

The compiled cutoff alone is compatible with source array capacities 240–287 bytes; the **exact 256** comes from the owner's same-checkout `include/linux/poll.h` macro report (header SHA `42b7aa8396b95893d943cafebb41030034a55df67b20e914040ea97545bedeb3`). The header bytes themselves were not included, so this header hash was *not* independently rechecked from raw uploaded bytes. The OEM compiler inputs, exact source-local stack coordinates, physical stack reuse, exploitation and KernelSU remain **UNVERIFIED**.

The compact machine-readable checkpoint is versioned under `research/y2q-G986U1UESCHXL1/select-numeric-crosswalk-20261014.json`. The next work should not repeat the buffer-threshold or missing-symbol work; it must address independent compiler-local evidence and deployment blockers. Source-level bitmap size does **not** establish a usable cross-function kernel stack overlap.

---

## October 14 — owner run resolves the exact header and native select threshold

The owner uploaded `hxl1-select-header-provenance-20261014.json` from the hash-pinned local checkout. The audit reports:

- Exact `kernel/futex.c` and `fs/select.c` checks passed using their previously recorded SHA256 pins.
- Same-checkout `include/linux/poll.h` SHA-256: `42b7aa8396b95893d943cafebb41030034a55df67b20e914040ea97545bedeb3`. **The header bytes themselves were not uploaded**, so this hash is owner-reported, not independently rehashed here.
- Original macro chain: `SELECT_STACK_ALLOC=FRONTEND_STACK_ALLOC` then `FRONTEND_STACK_ALLOC=256`. This verifies **256 source bytes** under the straightforward unpreprocessed alias-chain interpretation; OEM compiler header-input identity remains unproven.
- Previously archived disassembly SHA-256: `20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997`, with **5/5** saved text digests revalidated.
- The report correctly has `headerFactoryCompilerInputIndependentlyProven=false`, `oemCompiledStackLocalOffsetProven=false`, `runtimeStackReuseOrPrivilegeProven=false`.

**New independent original select-code arithmetic review:** from the uploaded original disassembly, `core_sys_select` clamps `n` to the fdtable limit, sign-extends the resulting count, adds 63, then right-shifts by six to calculate 64-descriptor word groups. The conditional branch selects on-stack storage when the rounded intermediate is below `0x180` (384). Therefore it takes the local path for `n <= 320`, and dynamic storage for `n >= 321` (assuming nonnegative `n`, after the source-verified reject-negative gate and fdtable clamp). The dynamic allocation uses `3 * groups << 4`, equivalent to **48 bytes per 64 descriptors**, i.e. six 8-byte bitmap words.

For **256 source bytes**, six equal bitmaps consume at most `6 * 5 * 8 = 240` bytes of the local array. This is an excellent source/binary consistency check: the compiled cutoff and scaling agree with the source's six-bitmaps-over-256-bytes logic. **But the observed cutoff does not uniquely authenticate 256**: any capacity from **240 through 287 source bytes** admits the same number of whole bitmap groups. The header provides the exact source declaration; the recovered machine code corroborates the allocation-path arithmetic, not an exact C-local extent or the OEM compiler's input provenance.

The repository's `tools/y2q_hxl1_select_header_provenance.py` now performs this numeric cross-check when a disassembly archive is supplied (beyond its earlier two static instruction anchors), rejects incorrect comparison/branch/allocation scaling, and explicitly reports the nonuniqueness caveat. Four additional synthetic regressions test these conditions. Those newly committed tests still require a confirmed CI or owner execution; do not claim that all tests passed simply because GitHub files were committed.

**Progress:** Original header macro gate `SOURCE_VERIFIED_BY_OWNER_REPORT`, compiled select allocation capacity `STATIC_CROSSWALK_CORROBORATED`; exact compiled stack-local object coordinate, futex/select stack reuse, runtime GhostLock and KernelSU remain `UNVERIFIED/BLOCKED`. No repeat firmware extraction, Clang ABI pass or device access required.

---

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
