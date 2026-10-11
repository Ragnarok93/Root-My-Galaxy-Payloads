# Galaxy S20+ HXL1 root-feasibility research: firmware first, no stock Image rebuild

**Current instructions (October 11, 2026):**
[HXL1 firmware-to-profile next steps](../../docs/SM-G986U1-HXL1-NEXT-STEPS.md).
This file is a chronological evidence record and contains historically
valid but **superseded** instructions. Do not restart an already-complete
firmware download/source extraction, Clang18 compilation, EFI static
analysis or duplicate-report campaign solely because older sections
say "next". Start with the nine-stage readiness checker and the
already implemented pinned-original-kernel source/code review.
The stock factory ABI, real runtime privilege and KernelSU remain
unverified.

**Target:** Samsung SM-G986U1 (y2q), firmware **G986U1UESCHXL1**,
Android 13, `uname -r = 4.19.113-27095354`, security patch
2025-01-01. The bootloader is locked, Android SELinux enforcing,
and the existing Shizuku/ADB identity probe ran as `uid=2000`.

**Nine-stage porting map:** [SM-G986U1 HXL1 adaptation](../../docs/SM-G986U1-G986U1UESCHXL1.md) follows `docs/PORTING.md` section-by-section and records completed input-evidence gates and open Linux 4.19 / KernelSU / feed milestones.

**Current deliverable:** a *read-only/offline source triage and
non-executable payload candidate manifest*, not a working root exploit.
No root was achieved, no bootloader lock state changed, and no KernelSU
module was installed.

## Research references and applicability

- [CVE-2026-43499 advisory](https://www.cve.org/CVERecord?id=CVE-2026-43499):
  Linux rtmutex `remove_waiter()` incorrectly treats `current` as
  the waiter task in a proxy-lock rollback path. This can leave stale
  kernel state. A Linux 4.19.x version is in the publicly documented
  affected ranges **unless a vendor-specific fix/backport exists**.
  That does not demonstrate Samsung HXL1 exploitability.
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia):
  original public CVE research and proof-of-concept.
- [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads):
  separate device payload/feed format. Do **not** copy 5.x/6.x offsets,
  exploit parameters, or KernelSU binaries to y2q.
- [wxxsfxyzm/GhostLock-Galaxy](https://github.com/wxxsfxyzm/GhostLock-Galaxy):
  Android shell/Shizuku route; its listed supported device is
  SM-F9560 on kernel 6.1.145, **not SM-G986U1**.
- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app):
  exact `uname -r` profile matching and pre-execution validation.
- [ccp-p/ghostlock-cve-2026-43499-4.19-k40](https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40):
  independent 4.19 Qualcomm-family adaptation, useful as evidence
  that this kernel **generation** merits research. It is on an
  entirely different device/firmware and does not establish support.

The existing Root-My-Galaxy app selects by model and truncated numeric
kernel version. That is too broad for experimental y2q support;
a research profile must remain outside `support/targets-v3.json`.
Any future y2q executable must require **exact model, firmware,
complete `uname -r`, fingerprint and original image hashes**.
`4.19.113` by itself is insufficient.

## Phase 1: read-only analysis of the original vendor source

The kernel tree reconstructed from 11 Samsung overlays and audited
against 40 known source hashes is at:

`~/src/samsung-y2q-hxl1-stock`

The separate VDSO compatibility trees and Clang18 O= output
exist only for **off-device kernel compilation**, which is not needed
for Phase 1. This tool uses the **original** source.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/assess_y2q_root_candidate.py \
  --evidence research/y2q-G986U1UESCHXL1/evidence.json \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --stock-source ~/src/samsung-y2q-hxl1-stock \
  --output ~/s20-artifacts/y2q-hxl1-root-candidate.json
```

Requirements and safety properties:

1. Exact hardware model `SM-G986U1`, firmware
   `G986U1UESCHXL1`, fingerprint, device name and **full**
   kernel release must match the existing hardware-verified
   evidence record.
2. The original Samsung source audit must verify its Makefile,
   **40/40 final overlay files** and official device config digests.
3. The tool reads only `kernel/locking/rtmutex.c` and
   `kernel/futex.c` to locate and report relevant control-flow
   patterns. These pattern checks are *heuristics*. It refuses to
   label the device exploitable or supported on their basis.
4. `CONFIG_FUTEX_PI=y`, `CONFIG_RANDOMIZE_BASE=y`,
   RKP/KDP/DEFEX and module-signature properties are retained
   as explicit constraints. Do not disable them.
5. Result is **metadata-only**:
   `executable=false`, `rootGranted=false`,
   `allowRegistrationInSupportFeed=false`,
   `deploymentBlocked=true`.
6. Outputs are write-once. An existing report is not overwritten;
   choose a fresh filename.

If you have the **original** extracted firmware images, you can
optionally add both flags and the hashes will be compared against
the verified `evidence.json` values:

```text
--boot-img /path/to/original/boot.img
--kernel-bin /path/to/original/kernel.bin
```

The tool will stop if even one byte differs from the expected
SHA-256; neither these images nor the original source are modified.

## Phase 2: candidate assessment gates

The report may classify the relevant source functions as:

- `REVIEW_REQUIRED_POSSIBLE_UNFIXED_CODE_PATH`: source pattern
  resembles the upstream bug; not proof of exploitability
- `REVIEW_REQUIRED_POSSIBLE_FIXED_CODE_PATH`: source pattern
  resembles the post-fix implementation; needs manual review
- `REVIEW_REQUIRED_AMBIGUOUS_CODE_PATH`: mixed or vendor-specific
  implementation; needs manual review
- `UNKNOWN_OR_VENDOR_DIFFERENT`: relevant functions/calls absent
  or renamed; the heuristic cannot conclude anything

Even a potentially unfixed rtmutex function does **not** prove that
the necessary userspace path, kernel memory primitive, address
discovery, security enforcement bypass, and KernelSU load mechanism
work on this firmware. Collect reproducible evidence for each
gate, test only on a personally controlled device, and maintain
a safe recovery plan before risky experiments.

The research report intentionally does not derive addresses,
construct kernel writes, race futex primitives, forge kernel
work structures, disable defenses, or launch privileged processes.

## Phase 3: readiness and integration

The user already ran the existing standalone
`research/y2q-G986U1UESCHXL1/identity_probe.c` under ADB shell
and confirmed a precise firmware match. This is an identity test,
**not** a CVE test.

We can build and run that *read-only* Android NDK identity probe
independently of any Samsung Image compilation:

```bash
ANDROID_NDK_HOME=/path/to/android-ndk \
  bash research/y2q-G986U1UESCHXL1/build_probe.sh
```

Only after independent, owned-hardware testing demonstrates an
approved working technique should implementation, payload compilation,
KernelSU compatibility and app integration be considered. Do not
register this research manifest into production feed schemas and
do not copy older kernel-family offsets, module binaries, or
workarounds into this device.

## Separate legacy-kernel compiler investigation

Existing `tools/build_samsung_stock_kernel.py` remains available for
reproducibility. Build-10 reached `arch/arm64/mm/cache.o` before
stopping for a **separate compilation failure** (the pasted tail
does not contain the underlying diagnostic). The present
root-feasibility path does **not** depend on resolving that build.


## October 10: dedicated HXL1 research toolchain, no full kernel rebuild

The device-specific pipeline is `tools/y2q_research_toolchain.py`.
It reuses **existing audited source/identity/CVE triage helpers**.
Neither the original Samsung source tree nor a Clang18-rebuilt kernel
is a prerequisite for compiling the **standalone Android NDK
identity diagnostic**. Source triage still requires the original
verified Samsung source.

The work is deliberately split into stages that cannot mistake a
generated file for a working root method:

| Stage | Output | What it actually proves |
|---|---|---|
| `references` | Local reference matrix | Comparison of published GhostLock projects, none claimed HXL1-compatible |
| `scan` | `candidate.json` | Exact identity + source provenance + heuristic CVE review |
| `build-probe` | ARM64 `.so` + SHA-256 manifest | Native Android diagnostic library compiles for API 33 and checks exact y2q/HXL1 |
| `bundle` | Write-once deterministic ZIP | Reproducible research artifact bound to one candidate manifest and binary hash |
| Root exploit development | **Blocked** | No HXL1 kernel primitive, root chain or KernelSU loader validated |

The original Root-My-Galaxy Android application already has an
Investigation workflow, device snapshot, and Shizuku shell access,
but **support feed schema v3 matches truncated numeric kernel
versions and model**, insufficient for this unverified 4.19 target.
Do not add HXL1 to `support/targets-v3.json`, change the Android
app's production payload selector, or expose a root action for
this device yet.

### Run the exact offline source/evidence scan

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
mkdir -p ~/s20-artifacts/hxl1-research

python3 tools/y2q_research_toolchain.py references

python3 tools/y2q_research_toolchain.py scan \
  --evidence research/y2q-G986U1UESCHXL1/evidence.json \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --stock-source ~/src/samsung-y2q-hxl1-stock \
  --output ~/s20-artifacts/hxl1-research/candidate.json
```

Optionally append `--boot-img /verified/original/boot.img`
and `--kernel-bin /verified/original/kernel.bin` *only when
those extracted files actually exist on WSL*. Both SHA-256 values
must match the firmware previously recorded in `evidence.json`.
Do not confuse an offline matching firmware image with a proven
live-boot-partition byte-for-byte dump.

The scan will describe the vendor `remove_waiter()` branch
classification. A pattern that resembles the public 2026 UAF
is a **review signal**, not proof that Android userspace can
reproduce a safe entry condition or that kernel protections can
be overcome. The report explicitly blocks exploit publication.

### Compile a firmware-locked, read-only ARM64 probe library

Requires an **Android NDK** installed in WSL. This is not the
Samsung kernel Clang18 toolchain and does not run Make on
any kernel sources.

```bash
export ANDROID_NDK_HOME="$HOME/android-ndk-r27d"  # adjust to actual installed path

python3 tools/y2q_research_toolchain.py build-probe \
  --scan-report ~/s20-artifacts/hxl1-research/candidate.json \
  --ndk "$ANDROID_NDK_HOME" \
  --output ~/s20-artifacts/hxl1-research/y2q-G986U1UESCHXL1-identity-diagnostic.so \
  --manifest ~/s20-artifacts/hxl1-research/binary.json
```

The new native library exports `rmg_y2q_probe_status()`,
`rmg_y2q_probe_euid()`, `rmg_y2q_probe_firmware()`, and
`rmg_y2q_probe_kind()`. It contains **no constructor,
kernel exploitation, root operation, module loader, ptrace
manipulation, or writes to the phone**. Its return code 0
means only that the device properties and running kernel match
the exact research profile.

The build checks for Linux ARM64 API33 Clang and validates the
result as ELF64 little-endian ET_DYN for AArch64. It records
the exact source checksum, scan-report checksum, binary
SHA-256, and non-deployability flags. Existing files cannot
be silently overwritten.

The separate existing
`research/y2q-G986U1UESCHXL1/identity_probe.c` standalone
program has already been device-tested as ADB shell uid 2000;
this new `.so` is a future app-integration building block,
not an additional hardware root test.

### Create a reproducible review package

```bash
python3 tools/y2q_research_toolchain.py bundle \
  --scan-report ~/s20-artifacts/hxl1-research/candidate.json \
  --library ~/s20-artifacts/hxl1-research/y2q-G986U1UESCHXL1-identity-diagnostic.so \
  --manifest ~/s20-artifacts/hxl1-research/binary.json \
  --output ~/s20-artifacts/hxl1-research/y2q-HXL1-diagnostics.zip

sha256sum ~/s20-artifacts/hxl1-research/y2q-HXL1-diagnostics.zip
```

The ZIP carries only source-analysis JSON, manifest,
a diagnostic library and disclaimer. **It is not an
installable exploit, does not grant root, and never enters the
production support feed.**

### GhostLock comparison notes (no cross-device offset reuse)

- [Linux CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499)
  documents `remove_waiter()` proxy-lock rollback, and fixes
  in supported kernel families. The reported kernel version
  4.19 predates the disclosure, but vendor-specific backports,
  booted-binary differences and runtime exploitability remain
  to be verified.
- [CyberMeowfia original research](https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499)
  is a source-level reference; its default target files are not
  Samsung HXL1 profiles.
- [ccp-p Qualcomm 4.19 adaptation](https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40)
  targets a Redmi K40/4.19.157 kernel. Kernel generation similarity
  helps select research questions but **does not justify importing
  its addresses, stack layouts, or runtime assumptions**.
- [GhostLock 4.19 adapter](https://github.com/XiaoBaiLovesStirring/ghostlock-k419-adapter)
  targets a separate 4.19.152-perf+ vendor build. Its stack
  feasibility script makes simplifying assumptions and must
  not be taken as an HXL1 validation result.
- [GhostLock-Galaxy](https://github.com/wxxsfxyzm/GhostLock-Galaxy)
  demonstrates an ADB/Shizuku shell execution route on
  Fold6 6.1.145, not this Galaxy S20+ kernel.
- [Samsung GhostLock research](https://github.com/Meowkis/ghostlock-samsung-research)
  provides evidence-traceable offsets on S23 Ultra, not
  values that can be reused on HXL1.

**Blocking next decision:** examine the `scan` classification and
manually compare the original HXL1 `rtmutex.c` implementation
with the upstream vulnerability fix. If the original firmware
contains an affected implementation, independently determine
which non-destructive runtime prerequisites can actually be
validated on the owner's phone. Never infer that a kernel
address, arbitrary read/write capability, working root shell,
or persistent KernelSU integration exists from this toolchain.


## October 10, 2026 — Stage 4 original EFI provider complete; pivot to honest Stage 3 kernel gating

The owner completed `bash tools/run_y2q_hxl1_envdxe_efi_pool_ownership.sh`
with **6,412/6,412 tests PASS** (14.554 seconds). The full static
`EFI_RAMPARTITION` callback and pool ownership are authenticated against
the exact `EnvDxe-HXL1.efi` digest
`9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670`:

- Callback `0x1f74` uses `0x2618 -> 0x25d8` to request
  `EfiBootServicesData` through `BootServices.AllocatePool(+0x40)`.
- It calls the original RAM provider at `0x52cc`, copies two 64-bit
  fields from `0x48`-stride internal records into `0x10`-stride
  EFI output entries, then calls `0x26bc` through
  `BootServices.FreePool(+0x48)`.
- The unrelated `0x3d04` code is a bounded byte-string-length helper,
  not the RAM partition record copier.
- **These are original static firmware instructions only**: no actual
  `SMEM_USABLE_RAM_PARTITION_TABLE` content, selected boot-time
  physical memory, per-boot KASLR, live root or KernelSU was measured.

The next investigation should not repeat ABI evidence for the EFI provider
without a material new fact. Exact Linux kernel structure layouts remain
unverified. Pinned original Samsung source headers and recovered `vmlinux`
symbols are **not** equivalent to the OEM's compiled `rt_mutex` member offsets.
The partial Clang18 build differs from the original factory Clang10 and
cannot establish factory field geometry even if DWARF type declarations
appear. The RT-mutex `current`/waiter source review resembles a published
vulnerability pattern, but does not demonstrate an executable or reliable
privilege-escalation path.

A new read-only tool `tools/y2q_hxl1_kernel_proof_matrix.py` therefore
executes and reconciles five previously independent, pinned local checks:
`y2q_stage3_layout_inventory`, `y2q_partial_samsung_dwarf_audit`,
`y2q_dwarf_type_presence`, `y2q_rtmutex_fix_audit`, and
`y2q_porting_readiness`. It uses each audit's **actual report field
schema**, checks explicit negative runtime/security claims, and reports
original source declarations, experimental type presence, effective
Clang18-vs-stock config differences, RT-mutex source-review signals, and all
nine readiness gates without manufacturing offsets.

Run on WSL2:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_kernel_proof_matrix.sh

Output:
`~/s20-artifacts/hxl1-research/kernel-proof-matrix.json` and
`~/s20-artifacts/hxl1-research/kernel-proof-matrix.md`.

**This is deliberately not a new root method, and does not contact the phone.**
Next proof obligations: OEM-equivalent compiled layouts (if recoverable),
a genuine unprivileged vulnerability applicability result (not just source
and syscall smoke tests), validated physical kernel handoff/KASLR data, and
feasible KernelSU loading under signature enforcement/RKP/KDP/DEFEX.
Production support feed registration stays disabled.


## October 10, 2026 — owner's Stage 3 kernel matrix passed: 102 checks, but factory layouts still absent

Owner executed `bash tools/run_y2q_hxl1_kernel_proof_matrix.sh` after pulling `28b40d1`. The runner reported **102/102 tests PASS** and authenticated exact original HXL1 stock kernel and source pins. Stage 3 remains **PARTIAL**, with nine stages still 1-2 COMPLETE, 3 PARTIAL, 4-6 OPEN, 7-8 BLOCKED, and 9 DEFERRED.

Actual retained experimental Clang18 build inventory: **85 objects**, **77 AArch64 ET_REL objects**, **72 with DWARF**. Explicit `pahole -C` complete-definition counts: **rt_mutex_waiter: 0; rt_mutex: 0**. All seven original Samsung source declarations were located, but **zero factory-compiled member layouts were proved**. Compiled debug data from Clang18 cannot be equated to Samsung's stock Clang10 layout. The RT-mutex current/waiter source pattern and public fix comparison remain *source-level only*; not verified on-device CVE applicability, kernel privilege escalation or KernelSU.

The report is preserved at `~/s20-artifacts/hxl1-research/kernel-proof-matrix.md`.

### Next focused diagnosis (not a root/exploit run)

Rather than accumulating more unsupported offsets, new `tools/y2q_hxl1_dwarf_gap_triage.py` inspects **six retained target object paths**, their original Kbuild `.cmd` debug-compiler switches, and their named `DW_TAG_structure_type` / `DW_TAG_class_type` records independently with `readelf --debug-dump=info --wide`. It distinguishes missing objects, ARM64 objects with no DWARF, forward/incomplete type records, complete *experimental* type records, and readelf/tool failures. It explicitly avoids parsing or exporting member locations; `DW_AT_byte_size` is checked only for completeness, not emitted as a factory size.

The tool refuses any evidence promotion to runtime kernel load, root, GhostLock applicability or KernelSU. Its 39 focused new regression cases and all preexisting CI checks passed in [GitHub Actions run 38097413820](https://github.com/Ragnarok93/Root-My-Galaxy-Payloads/actions/runs/38097413820): **6,941 repository tests PASS**. The owner's WSL host is still needed to inspect the actual retained `.o` and `.cmd` files.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_dwarf_gap_triage.sh

Expected reports:

- `~/s20-artifacts/hxl1-research/kernel-dwarf-gap-triage.md`
- `~/s20-artifacts/hxl1-research/kernel-dwarf-gap-triage.json`

Even a full experimental DWARF struct DIE does **not** authenticate an OEM kernel type layout. No flash, ADB, or connected S20+ is needed.


## October 10, 2026 — owner DWARF gap triage identifies two truly missing object outputs

The owner's `bash tools/run_y2q_hxl1_dwarf_gap_triage.sh` completed **141/141 tests PASS** after pulling `cbe1780`. The exact stock Samsung source/kernel and generated Clang18 `.config` pins matched. The retained Clang18 partial build consists of 85 objects, of which 77 are AArch64 ELF relocatables and 72 contain DWARF. Additional independent `readelf --debug-dump=info` inspection distinguishes missing compiled objects from forward declarations:

- `kernel/locking/rtmutex.o` — **OBJECT_MISSING**, no retained `.rtmutex.o.cmd` build command.
- `kernel/futex.o` — **OBJECT_MISSING**, no retained `.futex.o.cmd` build command.
- `init/init_task.o`, `init/main.o`, `arch/arm64/kernel/process.o` and `arch/arm64/kernel/fpsimd.o` — `rt_mutex_waiter` forward/incomplete DWARF DIE only (one each), zero complete `rt_mutex` DIEs. All four retained Kbuild `.cmd` files indicate `-g` debugging is enabled; none has a proven factory layout.

**Critical distinction:** The missing two objects do **not** prove either source file had a compiler error. The partial build may have stopped before Kbuild attempted these targets. The historical Build-10 tail was reported as reaching `arch/arm64/mm/cache.o`, without the original failure diagnostic. No kernel offsets, CVE exploit path, physical load, boot state or KernelSU is established.

To resolve this without guessing, `tools/y2q_hxl1_target_build_blockers.py` and `tools/run_y2q_hxl1_target_build_blockers.sh` now inspect the original Samsung Kbuild selection rules, stock configuration gates and **bounded historical build-log tails**, with optionally explicit log paths. Target-matching errors and unrelated compilation failures remain separate evidence classes, and missing build-log evidence is explicitly labelled **UNRESOLVED**. This is a completely **read-only** pass; it cannot compile or alter kernel source, build outputs, firmware or a connected device.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_target_build_blockers.sh

If the relevant prior compiler output is outside the discovered `~/s20-artifacts` location, use:

    bash tools/run_y2q_hxl1_target_build_blockers.sh --log /absolute/path/to/prior-build.log

Report: `~/s20-artifacts/hxl1-research/kernel-target-build-blockers.md` and `.json`.

A future debug build, if justified by actual compiler logs, should use a **separate O= output directory**, preserve the original source and pinned Clang18 `.config`, and remain non-deployable. A successful new Clang18 DWARF type definition would be provisional research information, not the OEM factory Clang10 ABI or permission to install KernelSU.


## October 10–11, 2026 — owner checked 20 historical logs; real Build-10 blocker is arch/arm64/mm/cache.o

The owner ran `bash tools/run_y2q_hxl1_target_build_blockers.sh`
after pulling `dd3c7da`. The run passed **295/295 offline
checks**, verified exact HXL1 stock `CONFIG_RT_MUTEXES=y`,
`CONFIG_FUTEX=y`, `CONFIG_FUTEX_PI=y` and `CONFIG_DEBUG_INFO=y`,
and confirmed these original Kbuild rules:
`kernel/locking/Makefile:24 -> obj-$(CONFIG_RT_MUTEXES) += rtmutex.o`,
`kernel/Makefile:60 -> obj-$(CONFIG_FUTEX) += futex.o`.

Original target build files `kernel/locking/rtmutex.o` and
`kernel/futex.o` and their `.cmd` compiler records remain **absent**
from the retained Clang18 partial build; **zero matching errors** appeared
in automatically discovered logs.

Unlike prior partial tail excerpts, the full preserved
`~/s20-artifacts/samsung-hxl1-image-clang18-build-10.log`
was located and showed a non-target compile failure:
`<instantiation>:2:2: error: unrecognized instruction mnemonic`
with Make terminating at `arch/arm64/mm/cache.o`
(`scripts/Makefile.build:438`) in the separate VDSO IAS formatting
compatibility tree. Build-09 stopped on Samsung's forbidden warning
at `main.c:720`, Build-08 at `seq_buf.h:35`, and prior builds
encountered VDSO link/assembly, cgroup macro/assembler toolchain issues.
No target-specific `rtmutex.o` or `futex.o` compile errors were
observed. **Do not attribute the partial-build stop to the absent
RT-mutex objects.**

A second user command used the illustrative, nonexistent
`--log /absolute/path/to/previous-build.log`. Earlier code
misleadingly accepted that missing explicit path, produced an empty
scan, and overwrote the preceding meaningful Markdown/JSON reports.
The revised tool now:
- **Rejects nonexistent/non-regular/symlinked explicit `--log` paths**,
  rather than creating a success report from no evidence.
- Restricts default autodiscovery to actual
  `samsung-hxl1-image-clang18-build[-NN].log` logs, not QEMU guest
  logs, Ghidra stderr or RT-mutex source excerpts.
- Preserves previous results using exclusively created versioned
  `-run-001`, `-run-002`, ... JSON and Markdown outputs.
- Displays the **current** report in the runner instead of `cat`ing
  stale default output.
- Prints bounded actual assembly error context around the original
  `unrecognized instruction mnemonic`, preserving source macro
  expansion evidence when present.

Next *read-only* host pass:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_target_build_blockers.sh

The full Build-10 context should determine whether the malformed
`cache.o` macro is specific to Clang18 integrated assembler or comes
from one of Samsung's assembly compatibility switches.
**No automatic recompile or source modifications are authorized by
this diagnostic.** A future isolated target-object compile can be
considered only after understanding this failure, and still cannot
prove factory Clang10 RT-mutex field offsets.


## October 10–11, 2026 — Build-10 Clang IAS error matches precise upstream Linux 4.19 fix

Owner's `bash tools/run_y2q_hxl1_target_build_blockers.sh --log
~/s20-artifacts/samsung-hxl1-image-clang18-build-10.log` passed **301/301
focused tests**, preserving a versioned `kernel-target-build-blockers-run-001.md`.
Original stock Kbuild enables both `rtmutex.o` and `futex.o`, and their
`.o/.cmd` absence has no target-specific compiler error. The actual
original Build-10 assembler diagnostics were:

    arch/arm64/mm/cache.S:126:1: note: while in macro instantiation
    alternative_if 27
    <instantiation>:2:2: error: unrecognized instruction mnemonic
    _ASM_EXTABLE 9999b, 9f

An exact upstream Linux **4.19-stable fix** exists: upstream commit
`6f5459da2b8736720afdbd67c4bd2d1edba7d0e3`,
"arm64: alternative: fix build with clang integrated assembler".
The AArch64 `.macro user_alt` uses the assembled lowercase
`_asm_extable`; GNU as historically tolerated an uppercase
`_ASM_EXTABLE` invocation, but Clang's integrated assembler did not.
This is **the identical error signature and instruction** in the
original upstream report:

- https://lkml.rescloud.iu.edu/2004.0/00879.html
- https://cos.googlesource.com/third_party/kernel/+/49275ad17f1a168f5b29ebd3832373cc0206d164
- https://lists.openwall.net/linux-kernel/2020/03/19/1728

Do not assume that the owner's original stock `alternative.h`
has the old macro until checking it. A new **optional** feature in
`tools/prepare_samsung_vdso_compat.py` performs that check,
accepts only the exact upstream one-line `user_alt` correction,
and creates a fourth-patch manifest with pinned file hashes and
normalized full-tree digest verification. Other source lines, the
Samsung original source tree and every previous experimental copy
remain unchanged. It does NOT change any security feature and
does NOT replace the original Qualcomm/Samsung factory compiler.

The new host-only runner defaults to dry-run; opt in to a **NEW**
isolated copy only after its stock preflight and exact substitution
checks pass:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_arm64_ias_extable_compat.sh
    # Only if the dry run verifies the exact stock source:
    bash tools/run_y2q_hxl1_arm64_ias_extable_compat.sh --execute

Expected new source:
`~/src/samsung-y2q-hxl1-vdso-ias-extable-compat`.
This must differ from existing
`~/src/samsung-y2q-hxl1-vdso-ias-format-compat` and the stock
`~/src/samsung-y2q-hxl1-stock`. Existing generated Clang18 `O=`
outputs are NOT reused as a validated new build. The runner does
**not** run `make`. Once the exact upstream patch is verified in
the new copy, any subsequent assembly/object compilation must use
a completely distinct `O=` directory and log, with its own
provenance and no claim that generated Clang18 DWARF yields factory
Clang10 `rt_mutex` member offsets.

**Current root milestone is still blocked:** no live physical load,
complete factory kernel field layouts, runtime GhostLock applicability,
temporary root or KernelSU. The compile workaround is diagnostic only.


## October 10–11, 2026 — source clone verified; fresh O=, object-only Clang18 experiment

Owner executed the validated four-patch preparation at commit `5b9fd1d`:

    bash tools/run_y2q_hxl1_arm64_ias_extable_compat.sh &&
    bash tools/run_y2q_hxl1_arm64_ias_extable_compat.sh --execute

Both original source/clone gates passed **43/43 tests**. The original
Samsung source fingerprint was `d8a04e191bd0df1521c5483dab441a71279e978ea207ea57681c1cfc49b4e11d`
and the resulting new experimental copy fingerprint was
`354b9f0e32a0b890babbc06470d9f9beb0cc2e8d069d7c73cdf5f6e2e9f0af5f`.
The exact original-to-compat `alternative.h` file SHA-256 transition was
`0a141774f5054ee2820cda7147eb3259dc702a2b993dbfd2bd40b23acbd18ac9`
→ `006bf2087b17b2bae9312a36c6e79c3c657ba0d55e6ce2484d745669a48252bf`.
**Only the isolated cloned source was created. No object build had been run**.

The next HXL1 Stage-3 diagnostic is implemented as
`tools/y2q_hxl1_isolated_dwarf_objects.py` and
`tools/run_y2q_hxl1_isolated_dwarf_objects.sh`. It shares the
source-preflight, compiler/linker probes, real Python 2.7 check, and
pinned `.config` SHA256 (`97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09`)
from the earlier original Clang18 experiment, but refuses to reuse the
existing partial `O=` tree. It uses:

- **Source:** `~/src/samsung-y2q-hxl1-vdso-ias-extable-compat`.
- **Template only:** `~/src/samsung-y2q-hxl1-config-clang18/.config`.
- **New output:** `~/src/samsung-y2q-hxl1-rtmutex-dwarf-ias-clang18`.
- **Object targets only:** `kernel/locking/rtmutex.o` and `kernel/futex.o`.
- **Log:** `~/s20-artifacts/samsung-hxl1-rtmutex-dwarf-ias-01.log`.
- **JSON:** `~/s20-artifacts/hxl1-research/rtmutex-dwarf-ias-01.json`.

Use the **dry run first**, confirming source/config and exact make
command identity without writing outputs:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_isolated_dwarf_objects.sh

Only if the dry run passes, opt in to fresh object compilation:

    bash tools/run_y2q_hxl1_isolated_dwarf_objects.sh --execute

The runner initializes the empty `O=` with the verified .config,
runs `olddefconfig`, verifies the config hash did **not** change, runs
`prepare`, verifies config again, then requests only the two objects.
A compiler, assembler or Kbuild failure stops at the actual stage;
original output/source are never modified by this tool. It preserves
the new `O=` and log for debugging rather than attempting an unsafe
resume or overwriting previous artifacts. An unsuccessful first attempt
requires a new distinct `--output/--log/--report` triplet.

Successful AArch64 relocatable objects are examined for named
`rt_mutex`/`rt_mutex_waiter` DWARF DIE presence (pahole + readelf),
but numeric member offsets are deliberately not harvested or
misrepresented as factory-layout offsets. **Even if both objects build,
Stage 3 is NOT complete**, because the Clang18 experimental ABI
is not the stock Samsung Clang10 ABI, the kernel physical handoff is
unknown, and no runtime GhostLock or KernelSU privilege path exists.
This pipeline does not flash, boot, install, sign or modify an Android
device.


## October 10, 2026 — owner target-only dry run blocked by missing host Python 2.7

The owner ran the new `run_y2q_hxl1_isolated_dwarf_objects.sh`
after pulling `dcbdeca`. The **62/62 offline regression tests passed**,
but the source/config build plan failed its **host toolchain preflight**
before `olddefconfig`, `prepare` or either object was compiled:

    [STOP] Samsung's kernel invokes /usr/bin/env python2.
    Install real Python 2.7 in an isolated prefix; do NOT alias python2 to python3.

This is **not a compiler error in rtmutex.o or futex.o**, and the
fresh output directory was **not created** by this run.

The driver now checks, in order, an explicitly passed `--python2` path,
`python2` on `PATH`, and user-local `~/.pyenv/versions/2.7.18/bin/python2`,
`~/.local/share/pyenv/versions/2.7.18/bin/python2`, and
`~/.local/python2.7/bin/python2`. Every candidate **must actually
execute as Python 2.7**, using the existing strict legacy-build version
probe. Python 3 shims and aliases are rejected.

If no isolated Python 2.7 already exists, one possible WSL/Ubuntu
approach is to install from the maintained [pyenv](https://github.com/pyenv/pyenv)
build tool without modifying the system-default Python interpreter:

    sudo apt-get update
    sudo apt-get install -y build-essential curl git make zlib1g-dev libssl-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev xz-utils
    if [ ! -d "$HOME/.pyenv" ]; then git clone https://github.com/pyenv/pyenv.git "$HOME/.pyenv"; fi
    "$HOME/.pyenv/bin/pyenv" install -s 2.7.18
    "$HOME/.pyenv/versions/2.7.18/bin/python2" -c 'import sys; assert sys.version_info[:2] == (2, 7)'

This is an **installation step on the owner's WSL host**, not an
operation performed by this GitHub-only work. Python 2.7.18 has been
end-of-life since 2020 and should be kept isolated for legacy build
scripts, never selected as the system Python or used for online services.
The official pyenv python-build instructions are at:
https://github.com/pyenv/pyenv/blob/master/plugins/python-build/README.md

Once a genuine Python2.7 is present, re-run the dry-run and only
then separately opt in to `--execute`. To select a different
already-installed interpreter:

    bash tools/run_y2q_hxl1_isolated_dwarf_objects.sh --python2 /absolute/path/to/python2

The subsequent Clang18 outputs and any DWARF records remain
**experimental**; none of this proves a factory Clang10 structure
layout, CVE applicability, root, physical addresses or KernelSU.


## October 10–11, 2026 — owner produced both Clang18 RT-mutex and futex object DWARF definitions

The owner installed real Python 2.7.18 to
`~/.pyenv/versions/2.7.18/bin/python2` and verified that runtime
(`sys.version_info[:2] == (2,7)`, GCC 13.3.0). Pulling `dd0ef18`,
the first
`bash tools/run_y2q_hxl1_isolated_dwarf_objects.sh --python2 "$PY2"`
dry run passed **68/68 local tests**, checked the exact original source,
the four-patch clone and pinned config, and did NOT modify anything.

The same runner invoked with `--execute` passed **68/68 tests** and
recorded **TARGET_COMMAND_COMPLETED**, with original object identities:

| Clang18-only AArch64 ET_REL object | SHA256 | DWARF | `pahole -C rt_mutex` | `pahole -C rt_mutex_waiter` |
|---|---|---|---|---|
| `kernel/locking/rtmutex.o` | `12279b4dfdf74425c47ef3514540ab1333fff1045fd6b066d378714707eed1f2` | Present | PRESENT | PRESENT |
| `kernel/futex.o` | `9adcfff8a44180d47bdb9f0ec40fb7ca646343eea939f74609f70b9975342e53` | Present | PRESENT | PRESENT |

Independent `readelf` source metadata reports **one complete
`DW_TAG_structure_type` definition for each type in each
object** (2 objects × 2 types = 4 confirmed complete DIEs). The
matching Clang18 `CONFIG_DEBUG_INFO=y` effective configuration
was pinned to SHA256
`97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09`.
Source tree and compatibility clone remained SHA256 pinned to
`d8a04e191bd0df1521c5483dab441a71279e978ea207ea57681c1cfc49b4e11d`
and `354b9f0e32a0b890babbc06470d9f9beb0cc2e8d069d7c73cdf5f6e2e9f0af5f`,
respectively. The build tool reported all three stages successful:
`olddefconfig`, `prepare` and exactly these two object targets.

Original build artifacts (do not overwrite):

- `~/src/samsung-y2q-hxl1-rtmutex-dwarf-ias-clang18/kernel/locking/rtmutex.o`
- `~/src/samsung-y2q-hxl1-rtmutex-dwarf-ias-clang18/kernel/futex.o`
- `~/s20-artifacts/samsung-hxl1-rtmutex-dwarf-ias-01.log`
- `~/s20-artifacts/hxl1-research/rtmutex-dwarf-ias-01.json`

This is a meaningful **experimental Clang18 compiled type-availability
milestone**. It does NOT complete firmware-to-profile Stage 3:
Samsung's factory build used a different compiler/toolchain (Clang10);
factory-equivalent numeric field layouts and live KASLR/physical kernel
addresses have not been proven. No payload, kernel Image, modules,
bootloader changes, privilege escalation, KernelSU or phone operation
was produced.

A new read-only post-build evidence audit in
`tools/y2q_hxl1_attest_isolated_dwarf_objects.py` now independently
SHA256-verifies both .o files, recomputes source/clone manifest
provenance, validates Kbuild's saved phase and config records and
re-probes both type definitions via readelf and pahole. It writes a
separate attestation report and never rewrites original artifacts:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_attest_isolated_dwarf_objects.sh

Expected output:
`~/s20-artifacts/hxl1-research/rtmutex-dwarf-ias-01-attested.md`
and `.json`. Full factory ABI equivalence, source-level CVE runtime
applicability, runtime privileged kernel state and KernelSU remain
explicitly **unverified**.


## October 10, 2026 — Owner source/object attestation PASS; next compare experimental TU geometry

Owner ran `bash tools/run_y2q_hxl1_attest_isolated_dwarf_objects.sh`
on original post-build artifacts after pulling `9f64b49`.
**94/94 regression tests PASS.** The independent checker verified:

- Original OEM source tree SHA256
  `d8a04e191bd0df1521c5483dab441a71279e978ea207ea57681c1cfc49b4e11d`.
- Four-patch experimental source SHA256
  `354b9f0e32a0b890babbc06470d9f9beb0cc2e8d069d7c73cdf5f6e2e9f0af5f`.
- Pinned experimental Clang18 `.config` SHA256
  `97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09`.
- Three successful original Kbuild phases, retained .cmd commands and
  matching exact compiled AArch64 ELF relocatable hashes:
  `kernel/locking/rtmutex.o` =
  `12279b4dfdf74425c47ef3514540ab1333fff1045fd6b066d378714707eed1f2`
  and `kernel/futex.o` =
  `9adcfff8a44180d47bdb9f0ec40fb7ca646343eea939f74609f70b9975342e53`.
- Both `pahole` and `readelf` independently verify one complete
  `rt_mutex` and one complete `rt_mutex_waiter` type definition per
  object.

Report:
`~/s20-artifacts/hxl1-research/rtmutex-dwarf-ias-01-attested.md`.
Only a **Python SyntaxWarning about escaped Markdown backticks** appeared;
the report generation and entire attestation completed successfully.
The backticks were corrected as Python literals by commit `9532595`.

### What this proves, and what remains missing

The two experimental Clang18 translation units really do contain
full DWARF declarations, but their agreement with one another has **not
yet been tested**. The original HXL1 stock kernel still has **no
verified independent field offsets or complete DWARF/BTF**, and a Clang18
type's byte size/offset cannot be passed off as the factory Clang10 ABI.
In particular no runtime privileged kernel access, KASLR address,
on-device exploit, KernelSU module, or installable payload has been shown.
Stage 3 remains PARTIAL; the later stages remain blocked/open.

New read-only checker:
`tools/y2q_hxl1_experimental_dwarf_tu_parity.py` independently inspects
the two **exact pinned original Clang18 objects** using readelf, checks
direct named-member count/order and raw location and bitfield
attributes, and computes SHA256 fingerprints of their geometry to detect
cross-translation-unit mismatch. Numeric offsets are **not exported**.
It is fail-closed on anonymous, absent, nonconstant or ambiguous field
locations. It intentionally does not compare embedded/nested type
definitions or type-reference targets, so even identical fingerprints
constitute **provisional partial geometry agreement**, not ABI equivalence.
The preparatory owner report attestation is run again first.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_experimental_dwarf_tu_parity.sh

Report:
`~/s20-artifacts/hxl1-research/rtmutex-experimental-tu-parity-01.md`.

**Regardless of this comparison, verifying the OEM factory ABI requires
additional independent stock-binary or matching toolchain/debug evidence**.
Don't promote internal Clang18 type agreement into a factory layout or
native exploit parameter.


## October 10–11, 2026 — Clang18 RT-mutex DWARF direct-member parity confirmed on WSL

Owner ran the new experimental two-translation-unit parity tool at
branch commit 44a56f3. All **51/51 focused regression tests passed**.
After independently re-attesting the exact rtmutex.o and futex.o SHA256
hashes, the owner received:

    [EXPERIMENTAL TU GEOMETRY] rt_mutex_waiter consistent True
    [EXPERIMENTAL TU GEOMETRY] rt_mutex consistent True

The two units agree on direct named-member count/order, aggregate
DWARF byte-size attributes, and direct member-location/bitfield
attribute fingerprints. This proves **provisional internal Clang18
build consistency**, not the ABI of Samsung's shipping Clang10 kernel.
Type references and nested embedded layouts were not independently
traced. The direct-member digest results are saved locally at
~/s20-artifacts/hxl1-research/rtmutex-experimental-tu-parity-01.md.

The next investigation now turns from experimental Clang18 object
confirmation to **independently pinned factory kernel code**. The new
tools/y2q_hxl1_stock_rtmutex_code_windows.py and
tools/run_y2q_hxl1_stock_rtmutex_code_windows.sh perform a read-only
selection from the original SHA256-pinned HXL1 kernel.bin. Candidate
RT-mutex/futex function names are sourced from previously recovered
vmlinux-stock.nm, whose labeling remains a separate static recovery
assumption. The tool bounds and hashes short original instruction
windows and uses aarch64-linux-gnu-objdump only to render the actual
code bytes. No offsets are inferred or applied; an instruction memory
displacement cannot independently be identified as a C member offset.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_stock_rtmutex_code_windows.sh

Expected report:
~/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows.md

**Stage 3 remains PARTIAL** until separately authenticated
source-to-instruction/compiled-member layout evidence is obtained.
Original symbolic virtual addresses do not establish live KASLR
or physical kernel load. A modern Clang18 match, field guess,
or original function-window hash cannot justify an executable
GhostLock payload, privileged kernel patch or KernelSU install.


## October 10–11, 2026 — owner verified 11 candidate stock RT-mutex code windows; full-symbol boundary correction

The owner ran `bash tools/run_y2q_hxl1_stock_rtmutex_code_windows.sh`
on the exact original HXL1 firmware and source. All **47/47 local
regression checks passed**, stock SHA256 preflight matched and
`aarch64-linux-gnu-objdump` decoded bounded original kernel Image
instructions for **11 recovered labels**, including
`rt_mutex_start_proxy_lock`, `rt_mutex_adjust_prio_chain`,
`remove_waiter`, `rt_mutex_init_proxy_locked`,
`rt_mutex_proxy_unlock`, `rt_mutex_trylock`,
`rt_mutex_lock`, `rt_mutex_unlock`,
`rt_mutex_lock_interruptible`, `rt_mutex_next_owner`, and
`futex_lock_pi`. The selected `futex_wait_requeue_pi` name did not
appear in this lookup; its absence from recovered kallsyms **does not
prove that the kernel feature or associated code is missing**.
The first report is preserved at
`~/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows.md`.

**Important tool correctness correction:** The first implementation
bounded each 192-byte code sample by the **next one of 12 selected
names**, accidentally allowing a sample to include unselected function
instructions that occur between those target names. No result can
safely be described as an isolated function window from that algorithm.

Version 2 uses the **entire original recovered ELF text-symbol address
set**, retains duplicate-named non-target boundaries, finds the next
strictly-greater text symbol for each selected function, and caps
window bytes to that boundary or the configured 192-byte maximum.
New targeted regressions cover intervening unselected functions,
duplicate non-target symbol names, same-address aliases, data labels,
misaligned boundaries, exact-end truncation, and reports showing how
many full-map code boundaries were considered. Previous 47 tests and
all existing CI checks pass. The code bytes remain original stock
Image bytes; the mapping to function names still rests on *recovered*
kallsyms and is not equivalent to independent OEM debug information.

**Run version 2** to produce a fresh report without overwriting the
owner's first snapshot:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_stock_rtmutex_code_windows.sh

The corrected, separate report is:
`~/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows-v2.md`.

This audit is **read-only**. Next step: inspect corrected instruction
windows along with stock-source functions for unambiguous evidence of
individual source-level accesses; until then **zero Samsung factory
structure offsets have been authenticated**. A recovered symbol VA is
not a running physical kernel address or known KASLR slide. A
working root method and KernelSU remain blocked.


## October 10–11, 2026 — original stock RT-mutex code-window v2 success and full source/code review

The owner ran `bash tools/run_y2q_hxl1_stock_rtmutex_code_windows.sh`
at commit 7b13995. All **54/54 focused regression tests passed**.
The original Samsung firmware/source hashes matched and 11/11 corrected
function-window samples from the SHA256-pinned original ARM64 Image
were fully disassembled using bounded recovered text-symbol windows.

The corrected boundaries reduced `rt_mutex_proxy_unlock` from
192 bytes to 24, `rt_mutex_lock_interruptible` from 192 to 104,
and `rt_mutex_next_owner` from 192 to 56. All other candidate
function-window byte counts were unchanged. A 192-byte excerpt
does not guarantee that a complete function was sampled.
Recovered static symbol assignments are not independently proven
factory debugger symbols or live runtime addresses.

The user-provided stdout includes function labels, sizes and success
statuses but **not the ARM64 instructions themselves**, so no reliable
field-offset or source-to-machine-code interpretation can yet be made.
The next host-only audit is
`tools/y2q_hxl1_stock_rtmutex_source_code_review.py` with runner
`tools/run_y2q_hxl1_stock_rtmutex_source_code_review.sh`.

The new tool independently checks ALL ELEVEN v2 window boundaries,
SHA256 digests and every decoded instruction word against the
pinned original `kernel.bin`; then rechecks the original two Samsung
C-file hashes and extracts uniquely located C function definitions for
`remove_waiter`, `rt_mutex_start_proxy_lock`, and `futex_lock_pi`.
It prints the original source and its corresponding **name-matched**
bounded ARM64 disassembly directly to the owner's console. It explicitly
cannot prove which individual C field an instruction accesses and
does not substitute experimental Clang18 offsets for factory ABI.

Next read-only WSL2 step:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_stock_rtmutex_source_code_review.sh

New immutable report outputs:
`~/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-source-code-01.md`
and `.json`. Original and v2 code-window reports remain preserved.

**Current gates:** Factory Clang10/stock compiled field layouts and
source-to-binary dataflow remain unverified. Static symbol locations
do not establish runtime physical kernel load, KASLR slide, exploit
applicability or KernelSU. No compilation or phone changes occur.


## October 11, 2026 — owner recovered full HXL1 stock `remove_waiter` code interval

Owner executed a direct read-only Python/objdump procedure using the
already existing `tools/y2q_hxl1_stock_rtmutex_code_windows.py`,
original `kernel.bin`, and recovered `vmlinux-stock.nm`. The original
kernel image SHA256 matched
`ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.
The recovered `remove_waiter` symbol begins at static
`0xffffff8008147db4` and the next *recovered* text-symbol boundary is
`0xffffff8008147fec`, giving **568 original stock Image bytes**
with SHA256
`f50dd6d1df275e0854e7d255c7f47abff81e2b065977e4a11b56007aa89d0c44`.
The previous 192-byte review was necessarily truncated; this pass
captured a normal return at `0xffffff8008147f80`, exceptional
`brk #0x800` paths at `0xffffff8008147fdc` and `...7fe0`,
and trailing NOP/data. The 568-byte interval **is not entirely
executable instructions** or a factory DWARF-authenticated function size.

**Concrete stock-code observations and provenance limits:**

- At entry `x0 = lock`, `x1 = waiter`; `x19` saves `lock`
  and `x23` saves `waiter`, until later reassignments.
  `ldr x22, [x0,#24]` followed by
  `ldr x8,[x22,#56]` and `cmp x8,x19` is consistent with
  a top-waiter pointer and the waiter's lock-pointer consistency check
  on the owner-provided original `rtmutex.c`, but not a BTF field-name
  record.
- `mrs x20,sp_el0` is the standard current-task access pattern
  in the observed kernel. `add x21,x20,#0x8c8` before lock calls
  and `str xzr,[x20,#2296]` (hex `0x8f8`) between them
  closely track original source lines 1077–1080
  (`raw_spin_lock(&current->pi_lock)` and
  `current->pi_blocked_on=NULL`); this is a **high-confidence
  stock-compiled source/dataflow hypothesis**, not a second
  independently authenticated debug-layout record.
- `ldr x24,[x19,#32]` followed by
  `and x21,x24,#~1` on the continuing path
  is consistent with `rt_mutex_owner(lock)`'s tagged
  owner-pointer handling. `add x22,x21,#0x8c8` supplies
  a candidate owner-task spin-lock address.
- Later `ldr x8,[x21,#2272]` (hex `0x8e0`),
  `ldr x8,[x21,#2296]` (hex `0x8f8`), then
  `ldr x23,[x8,#56]` are consistent with owner PI
  waiter/blocking references and the original
  `task_blocked_on_lock(owner)` flow.
- The six argument-register values loaded before
  `bl 0xffffff8008146ca4` match the original
  `rt_mutex_adjust_prio_chain(owner,RT_MUTEX_MIN_CHAINWALK,
  lock,next_lock,NULL,current)` calling convention.
  The recovered symbol at that exact call destination is still to be
  confirmed against the retained `vmlinux-stock.nm`.
- Independently from the same stock kernel sample, the
  `rt_mutex_start_proxy_lock` caller at
  `0xffffff8008147d58` executes a direct
  `bl 0xffffff8008147db4` on its error cleanup,
  consistent with original source line 1806
  `remove_waiter(lock,waiter)`. **Do not confuse**
  this wrapper with the separate internal
  `__rt_mutex_start_proxy_lock` called from
  `futex_lock_pi`'s original C implementation.

**Next useful existing-tool check, no new analyzer:**
read the already pinned `vmlinux-stock.nm` names for
`0xffffff8008146ca4`, `0xffffff80080fafb4`,
`0xffffff800996d544`, `0xffffff800996d774`,
`0xffffff800996d664`, and `0xffffff800996d83c`.
Review the matching source definitions in stock
`include/linux/rtmutex.h`, `include/linux/sched.h`, and
`kernel/locking/rtmutex.c` before accepting a member association.
An original source + original machine-code match is more informative
than the experimental Clang18 object, but **does not by itself prove
all OEM sizes, layouts, aliases or runtime kernel KASLR/base**.
Stage 3 remains PARTIAL; KernelSU and live vulnerability feasibility
are still unverified.


## October 11, 2026 — all six original `remove_waiter` call destinations resolved in owner WSL

Owner pulled commit `e6ebf51` and ran a targeted read-only
lookup against the already recovered, original HXL1
`~/s20-artifacts/hxl1-research/vmlinux-stock.nm`.

**All six requested targets were found**:

| Static original HXL1 address | Recovered symbol |
|---|---|
| `ffffff80080fafb4` | `T rt_mutex_setprio` |
| `ffffff8008146ca4` | `t rt_mutex_adjust_prio_chain` |
| `ffffff800996d544` | `T _raw_spin_lock` |
| `ffffff800996d664` | `T _raw_spin_lock_irq` |
| `ffffff800996d774` | `T _raw_spin_unlock` |
| `ffffff800996d83c` | `T _raw_spin_unlock_irq` |

This directly corroborates the **call graph** of the stock
`remove_waiter` disassembly. For example, `bl 0xffffff8008146ca4`
is a symbol-resolved call to `rt_mutex_adjust_prio_chain`, and
`bl 0xffffff80080fafb4` is a symbol-resolved call to
`rt_mutex_setprio`. It also establishes named original-kernel
lock/unlock callees, consistent with the two lock-management phases
visible in original source lines 1077–1118. Note: recovered
kallsyms names are not factory DWARF and an address's symbolic
identity is not proof of the data structure layout.

The same owner run inspected the **exact original Samsung source**:

- `include/linux/rtmutex.h:30–43` defines `struct rt_mutex` with
  `wait_lock`, `waiters` (`rb_root_cached`) and `owner`;
- `include/linux/sched.h:1169` includes
  `task_struct.pi_lock`, line 1175 `pi_waiters`, line 1177
  `pi_top_task` and line 1179 `pi_blocked_on`.

Together, stock function code, resolved call destinations and
original declarations support **high-confidence source/code
correlation** for `current->pi_lock`, the clear of
`current->pi_blocked_on`, and lock owner access (e.g. stock
`ldr x24,[x19,#32]` and tagged-owner masking). Other
`rt_mutex_waiter` and red-black tree nested layout and
task structure fields remain incompletely verified; the original
kernel's full factory DWARF/BTF was **not** recovered.
No experimental Clang18 field values should be treated as OEM
evidence. This evidence is **static original kernel code only**;
no on-device exploit, runtime KASLR/physical load proof,
or KernelSU result has been established.

**Next targeted check:** Inspect original `struct rt_mutex_waiter`
definition (commonly `kernel/locking/rtmutex_common.h`), the
`rt_mutex_top_waiter` and `rt_mutex_owner` helper definitions,
and `task_blocked_on_lock` at source level; compare only the
particular observed original ARM64 accesses. Do **not** run another
generic Clang18 DWARF compilation campaign or broad Ghidra pass.


## October 11, 2026 — direct original RT-mutex nested source declarations corroborate selected stock instructions

Owner pulled `fdc52d0` and inspected the original hash-pinned Samsung source
`kernel/locking/rtmutex.c`,
`kernel/locking/rtmutex_common.h`, and
`include/linux/rtmutex.h`. The relevant full output was supplied
from WSL2 and establishes the following **source facts**:

- `rtmutex_common.h:27` defines `struct rt_mutex_waiter` with
  `tree_entry: struct rb_node`, `pi_tree_entry: struct rb_node`,
  `task: struct task_struct *`, `lock: struct rt_mutex *`,
  conditionally compiled debug members, followed by `prio`.
- `rtmutex_common.h:53–62` implements `rt_mutex_top_waiter()`
  via `rb_first_cached(&lock->waiters)`,
  `rb_entry(...,struct rt_mutex_waiter,tree_entry)`,
  and `BUG_ON(w->lock != lock)`.
- `rtmutex_common.h:108–113` implements `rt_mutex_owner()` by
  reading the owner and masking `RT_MUTEX_HAS_WAITERS=1UL`.
- `rtmutex.c:380–383` defines
  `task_blocked_on_lock(p) = p->pi_blocked_on ?
  p->pi_blocked_on->lock : NULL`.
- `rtmutex.h:30–43` lists `struct rt_mutex` fields
  `wait_lock`, `waiters`, and `owner`.
  `sched.h:1169–1179` lists the task PI fields.

Cross-correlate with the **previously SHA256-pinned original stock**
`remove_waiter` function, length 568 bytes, SHA256
`f50dd6d1df275e0854e7d255c7f47abff81e2b065977e4a11b56007aa89d0c44`:

| Original stock instruction evidence | High-confidence function-local interpretation | Proof limit |
|---|---|---|
| `ldr x22,[x0,#24]`; `ldr x8,[x22,#56]`; `cmp x8,x19` | cached top waiter pointer then `waiter->lock` consistency check against lock | field association source/code-correlated, not factory DWARF |
| `ldr x24,[x19,#32]`; `and x21,x24,#~1` | `rt_mutex.owner` tagged owner-pointer extraction | tag handling confirmed by source |
| `mrs x20,sp_el0`; `add x21,x20,#0x8c8`; `str xzr,[x20,#2296]` | current task PI lock, clearing PI-blocked-on state | compiler use of `sp_el0` corroborated by task-based call flow, not a live runtime measurement |
| `ldr x8,[x21,#2272]`, `ldr x8,[x21,#2296]`, `ldr x23,[x8,#56]` | owner task PI waiter state, then blocked-on waiter and its `lock` | derived along one flow; no complete `task_struct` layout |
| `ldr w10,[x0,#64]` where `x0` is the selected top waiter | waiter `prio` in the non-debug field path | condition on `CONFIG_DEBUG_RT_MUTEXES` must be confirmed before exporting as unconditional |
| `bl 0xffffff8008146ca4` and `bl 0xffffff80080fafb4` | `rt_mutex_adjust_prio_chain` and `rt_mutex_setprio` | exact names verified against recovered stock kallsyms; no OEM type debug info |

The original `rb_node`/cached-root layout is consistent with the
above observed pointer access relationships. This narrows **selected
factory-compiled field-access hypotheses**, but does **not** prove all
nested aggregate sizes, conditional fields, aliases, or exact ABI
surface required by a native/kernel-resident payload. Stage 3 must
remain **PARTIAL**; do not promote the whole factory ABI based on
a handful of original operations. The original Clang18 objects remain
experimental, supplementary evidence only.

**Investigation pivot (avoid repetitive static analyzers):** The exact
original ABL LinuxLoader **static kernel handoff** was already
recovered, and prior owner read-only ADB evidence did not resolve
actual selected UEFI/base-memory branch values, boot-time DTB,
per-boot physical entry or KASLR displacement. The feasibility gates
now require independent, authorized **runtime** information and
the Linux 4.19 privilege/module-hooking path; further Clang18
compilation or identical RT-mutex lookups are not a substitute.
Refer to the canonical [HXL1 execution guide](../../docs/SM-G986U1-HXL1-NEXT-STEPS.md).


## October 11, 2026 — two saved stock HXL1 ADB reports reveal bootloader DTB/DTBO indices

The owner inspected **existing** read-only ADB JSON reports only,
without reconnecting the phone, modifying Android or collecting
additional private boot arguments. The observations are identical:

| Report UTC | `ro.boot.dtb_idx` | `ro.boot.dtbo_idx` | `/proc/iomem` | model/bootargs DTFS | physical load / per-boot KASLR |
|---|---|---|---|---|---|
| `20261010T130008Z` | `0` | `2` | `PERMISSION_DENIED` | `PERMISSION_DENIED` | unverified |
| `20261010T130021Z` | `0` | `2` | `PERMISSION_DENIED` | `PERMISSION_DENIED` | unverified |

`/proc/cmdline` was also `PERMISSION_DENIED`, and
`/proc/bootconfig` `NOT_PRESENT`. These are captures 13 seconds
apart, **not two independently verified boots**. The property
values are meaningful runtime *bootloader-provided index clues*,
not a file hash of the final running tree, a kernel physical
address or a KASLR measurement.

The original SHA256-pinned HXL1 boot-v2 embedded DTB region has
**four contiguous FDTs**, in the offline inventory's **one-based**
reporting order:

| Offline candidate | Region byte offset | Original root model | SHA256 |
|---|---|---|---|
| 1 | `0x0` | Qualcomm Technologies, Inc. kona v2.1 SoC | `b3aeb34a66528accde7ff21e1739224aa89a327595b99ea781bf4eb7b195b422` |
| 2 | `0x81088` | Qualcomm Technologies, Inc. kona v2 SoC | `d68acf630e4473bcc0341d83055f8308ccdaeb745f779e93d335ec58e7fec0d6` |
| 3 | `0x10210c` | Qualcomm Technologies, Inc. kona v1 SoC | `b463d63283610c577a1d0ad9c003d323dee6a79bb30e408c739110d45ba8d57f` |
| 4 | `0x181c46` | Minimal 173-byte FDT, no root model | `0bd849a7ed78287c8d0214ffeb56b3980a4379190a7e147adbfa063c9d712f0c` |

**Do not convert** `ro.boot.dtb_idx=0` to offline
candidate 1 without evidence that the same bootloader index
domain (base, ordering, image component, and selection) applies.
The four raw concatenated FDTs have **no Android DT_TABLE_MAGIC**
wrapper in original `boot.img`. Actual index semantics or
matching running-tree hash are not established.
`ro.boot.dtbo_idx=2` refers to a *distinct DTBO selection domain*;
the original selected DTBO table entry, overlay bytes, and
provenance have not been authenticated by the existing four-FDT
inventory. In particular **DO NOT call candidate 3 the selected
DTBO** simply because its one-based index is 3.

**Next only-if-useful existing-artifact gate:** First list any
already present exact-original `dtbo.img` or `dtbo.img.lz4`
under `~/s20-artifacts`, including provenance and hash if
present. If none exists, record
`HXL1_ORIGINAL_DTBO_TABLE_NOT_IN_LOCAL_EVIDENCE`.
Do not rerun denied ADB commands or substitute a current
Samsung FUS firmware/other device's DTBO. Stage 4 and Stage 5
remain OPEN. Module signature enforcement, disabled kprobes
and a locked bootloader keep KernelSU blocked until an
authorized runtime privilege/loading and compatible
Linux 4.19 hook path is demonstrated.


## October 11, 2026 — original DTBO missing from scoped local artifact search; no more DTB scans

Owner ran the current HXL1 next-steps host-only inventory check
on branch `688574e`. The `find` command returned **no files**
matching `dtbo.img`, `dtbo.img.lz4`, or `dtbo.bin`
within **five directory levels of `~/s20-artifacts`**.
Evidence status:
`HXL1_ORIGINAL_DTBO_TABLE_NOT_IN_LOCAL_EVIDENCE`.
This is a **bounded absence of the named extracted artifacts**,
not proof that original Samsung firmware lacks a DTBO partition,
and does not survey other host folders or alternative filenames.

The owner simultaneously confirmed the **pre-existing,
checksum-authenticated embedded base FDT inventory** is unchanged:

| Candidate (offline report numbering) | Root model | SHA256 |
|---|---|---|
| 1 | Kona v2.1 | `b3aeb34a66528accde7ff21e1739224aa89a327595b99ea781bf4eb7b195b422` |
| 2 | Kona v2 | `d68acf630e4473bcc0341d83055f8308ccdaeb745f779e93d335ec58e7fec0d6` |
| 3 | Kona v1 | `b463d63283610c577a1d0ad9c003d323dee6a79bb30e408c739110d45ba8d57f` |
| 4 | Minimal root FDT | `0bd849a7ed78287c8d0214ffeb56b3980a4379190a7e147adbfa063c9d712f0c` |

The two existing ADB snapshots' `dtb_idx=0`, `dtbo_idx=2`
still **cannot authenticate the final loaded base tree or
overlay**. `dtbo_idx` is not an index into these four
boot.img base FDT candidates. Do not repeat restricted ADB
reads, static DTB scans, or initiate a replacement
firmware download merely to fill this noncritical evidence gap.

**Root-feasibility decision:** Stage 3 remains PARTIAL, Stage 4
physical boot and Stage 5 per-boot runtime proofs OPEN;
Stage 6 native target OPEN; Stage 7 KernelSU and Stage 8
production feed BLOCKED. None of those classifications is
advanced by absence of local DTBO files.

The highest-impact **independent** unresolved question is
whether the original HXL1 `remove_waiter` source issue is
**dynamically reproducible and can provide controlled privileged
code execution** under stock Samsung protections.
Existing evidence establishes source-level bug-pattern and
stock instruction correlations only; the QEMU laboratory
runs **upstream 4.19.325**, not a bit-identical Samsung HXL1
kernel, and has only passed bounded uncontended futex-PI tests,
**not a vulnerability reproduction**. Any further vulnerability
work should start with a *safe, isolated, instrumented,
source-exact regression* (no real phone crash/race attempts),
and must explicitly distinguish reachability/logic failure
from an arbitrary kernel-write primitive or working root.

Separately, `CONFIG_MODULE_SIG_FORCE=y` and
`CONFIG_KPROBES=n` still block the current conventional
unsigned module/kprobe KernelSU approach. Never infer
KernelSU compatibility or a safe loader from a
vulnerability source pattern alone. There is no basis
for a working HXL1 root or installation claim yet.


## October 11, 2026 — use existing REA/Ghidra index-handling evidence rather than another static inventory

The owner ran the targeted host-only DTBO file-name inventory
(`dtbo.img`, `dtbo.img.lz4` or `dtbo.bin`, regular files at
depth <=5 under `~/s20-artifacts`). **No file names matched.**
The previously authenticated four original base-FDT candidate
SHA256/model results reappeared, with no changes or inconsistencies.
This does **not** prove the AP firmware archive contains no DTBO.

Correct next tool: the user's working [REA fork](https://github.com/Ragnarok93/rea)
(Ghidra 12.1.4 backend) already imports the original SHA256-pinned
`LinuxLoader-HXL1.efi` and retains verified PE search evidence for
`androidboot.dtb_idx=` at `0xbfd99` and `androidboot.dtbo_idx=`
at `0xbfd82`. The short REA-first runbook is now at the top of
[the canonical execution guide](../../docs/SM-G986U1-HXL1-NEXT-STEPS.md).
It runs exactly **two Ghidra xrefs** on those known original string
addresses, saves immutable fresh output and uses existing
`y2q_linuxloader_rea_stage4_xrefs.parse_xrefs` to validate Ghidra
provider, operation, query, PE digest and evidence IDs.

Only if original xref source instructions are found should the next
step use `rea function` for their owning routines and
`rea trace-native-values` for specific verified high-p-code dataflow
connections to `FUN_00023bc8` / BootLinux. A zero-reference result
is not proof the index lacks handling. Static index generation cannot
establish what DTBO bytes actually exist in the running device or
where the kernel resides in RAM. Full root, KernelSU and runtime
physical handoff remain unverified.


## October 11, 2026 — owner verified exact original HXL1 LinuxLoader DTB/DTBO string xrefs through REA

Using the locally installed REA fork and Ghidra, with the original
LinuxLoader PE SHA256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`
checked immediately beforehand, the owner invoked
`rea xrefs --provider ghidra --json` on the *existing* known
firmware string coordinates and then successfully authenticated
both results with the existing `parse_xrefs` original-PE validator:

| Original Ghidra PE string address | Exact static string | Source instruction | Verified REA Evidence |
|---|---|---|---|
| `0xbfd99` | `androidboot.dtb_idx=` | `0x2c350` | `ev_b31e5021edd1b1d5db9ff58336bb5e0f0abc3ff1d8e2189e6ce93363a5c796db` |
| `0xbfd82` | `androidboot.dtbo_idx=` | `0x2c308` | `ev_14dae88115f0805e73bc32804d89232d6212f4d3e65c777c335cd9ff09557a1b` |

Each literal string had exactly **one** recovered Ghidra
reference. The instruction coordinates differ by `0x48`
(72 bytes), which makes a shared originating function plausible,
**but the function identity/body has not been proven**.
The new local evidence files are under
`~/s20-artifacts/hxl1-research/abl-linuxloader/rea-dt-index-LBaPQ6`.

**Immediate next gate:** REA `function` queries for precisely
`0x2c350` and `0x2c308`, validated with the existing
`y2q_linuxloader_rea_stage4_functions.validated` helper and
reported function entry/body/HighFunction availability.
The exact WSL read-only procedure is now at the top of
[`docs/SM-G986U1-HXL1-NEXT-STEPS.md`](../../docs/SM-G986U1-HXL1-NEXT-STEPS.md).
Use `trace-native-values` selectively after actual owning
functions and value origins are identified; do not blindly
repeat prior broad searches. These are **static software facts**,
not runtime index-domain-to-overlay mapping or evidence
of actual `kernel_phys_load`, root or KernelSU.
