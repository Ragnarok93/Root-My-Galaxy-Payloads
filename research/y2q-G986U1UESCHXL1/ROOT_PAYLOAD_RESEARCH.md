# Galaxy S20+ HXL1 root-feasibility research: firmware first, no stock Image rebuild

**Target:** Samsung SM-G986U1 (y2q), firmware **G986U1UESCHXL1**,
Android 13, \`uname -r = 4.19.113-27095354\`, security patch
2025-01-01. The bootloader is locked, Android SELinux enforcing,
and the existing Shizuku/ADB identity probe ran as \`uid=2000\`.

**Current deliverable:** a *read-only/offline source triage and
non-executable payload candidate manifest*, not a working root exploit.
No root was achieved, no bootloader lock state changed, and no KernelSU
module was installed.

## Research references and applicability

- [CVE-2026-43499 advisory](https://www.cve.org/CVERecord?id=CVE-2026-43499):
  Linux rtmutex \`remove_waiter()\` incorrectly treats \`current\` as
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
  exact \`uname -r\` profile matching and pre-execution validation.
- [ccp-p/ghostlock-cve-2026-43499-4.19-k40](https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40):
  independent 4.19 Qualcomm-family adaptation, useful as evidence
  that this kernel **generation** merits research. It is on an
  entirely different device/firmware and does not establish support.

The existing Root-My-Galaxy app selects by model and truncated numeric
kernel version. That is too broad for experimental y2q support;
a research profile must remain outside \`support/targets-v3.json\`.
Any future y2q executable must require **exact model, firmware,
complete \`uname -r\`, fingerprint and original image hashes**.
\`4.19.113\` by itself is insufficient.

## Phase 1: read-only analysis of the original vendor source

The kernel tree reconstructed from 11 Samsung overlays and audited
against 40 known source hashes is at:

\`~/src/samsung-y2q-hxl1-stock\`

The separate VDSO compatibility trees and Clang18 O= output
exist only for **off-device kernel compilation**, which is not needed
for Phase 1. This tool uses the **original** source.

\`\`\`bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/assess_y2q_root_candidate.py \
  --evidence research/y2q-G986U1UESCHXL1/evidence.json \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --stock-source ~/src/samsung-y2q-hxl1-stock \
  --output ~/s20-artifacts/y2q-hxl1-root-candidate.json
\`\`\`

Requirements and safety properties:

1. Exact hardware model \`SM-G986U1\`, firmware
   \`G986U1UESCHXL1\`, fingerprint, device name and **full**
   kernel release must match the existing hardware-verified
   evidence record.
2. The original Samsung source audit must verify its Makefile,
   **40/40 final overlay files** and official device config digests.
3. The tool reads only \`kernel/locking/rtmutex.c\` and
   \`kernel/futex.c\` to locate and report relevant control-flow
   patterns. These pattern checks are *heuristics*. It refuses to
   label the device exploitable or supported on their basis.
4. \`CONFIG_FUTEX_PI=y\`, \`CONFIG_RANDOMIZE_BASE=y\`,
   RKP/KDP/DEFEX and module-signature properties are retained
   as explicit constraints. Do not disable them.
5. Result is **metadata-only**:
   \`executable=false\`, \`rootGranted=false\`,
   \`allowRegistrationInSupportFeed=false\`,
   \`deploymentBlocked=true\`.
6. Outputs are write-once. An existing report is not overwritten;
   choose a fresh filename.

If you have the **original** extracted firmware images, you can
optionally add both flags and the hashes will be compared against
the verified \`evidence.json\` values:

\`\`\`text
--boot-img /path/to/original/boot.img
--kernel-bin /path/to/original/kernel.bin
\`\`\`

The tool will stop if even one byte differs from the expected
SHA-256; neither these images nor the original source are modified.

## Phase 2: candidate assessment gates

The report may classify the relevant source functions as:

- \`REVIEW_REQUIRED_POSSIBLE_UNFIXED_CODE_PATH\`: source pattern
  resembles the upstream bug; not proof of exploitability
- \`REVIEW_REQUIRED_POSSIBLE_FIXED_CODE_PATH\`: source pattern
  resembles the post-fix implementation; needs manual review
- \`REVIEW_REQUIRED_AMBIGUOUS_CODE_PATH\`: mixed or vendor-specific
  implementation; needs manual review
- \`UNKNOWN_OR_VENDOR_DIFFERENT\`: relevant functions/calls absent
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
\`research/y2q-G986U1UESCHXL1/identity_probe.c\` under ADB shell
and confirmed a precise firmware match. This is an identity test,
**not** a CVE test.

We can build and run that *read-only* Android NDK identity probe
independently of any Samsung Image compilation:

\`\`\`bash
ANDROID_NDK_HOME=/path/to/android-ndk \
  bash research/y2q-G986U1UESCHXL1/build_probe.sh
\`\`\`

Only after independent, owned-hardware testing demonstrates an
approved working technique should implementation, payload compilation,
KernelSU compatibility and app integration be considered. Do not
register this research manifest into production feed schemas and
do not copy older kernel-family offsets, module binaries, or
workarounds into this device.

## Separate legacy-kernel compiler investigation

Existing \`tools/build_samsung_stock_kernel.py\` remains available for
reproducibility. Build-10 reached \`arch/arm64/mm/cache.o\` before
stopping for a **separate compilation failure** (the pasted tail
does not contain the underlying diagnostic). The present
root-feasibility path does **not** depend on resolving that build.
