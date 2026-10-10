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
