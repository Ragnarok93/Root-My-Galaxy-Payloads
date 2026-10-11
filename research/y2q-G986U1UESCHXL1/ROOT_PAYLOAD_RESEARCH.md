# Galaxy S20+ HXL1 root-feasibility research: firmware first, no stock Image rebuild

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
