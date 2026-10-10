# SM-G986U1 / G986U1UESCHXL1 — firmware-to-profile adaptation

**Status: RESEARCH ONLY — NOT ROOTED, NOT INSTALLABLE, NOT IN SUPPORT FEED.**

This document specializes [PORTING.md](PORTING.md) for the owner's US unlocked
Galaxy S20+ (`SM-G986U1`, `y2q`, Snapdragon 865/Qualcomm Kona) on Samsung
Android 13 firmware `G986U1UESCHXL1`. It describes **which porting steps
are supported by existing evidence**, which must be re-derived for Linux
`4.19.113`, and the sequencing/gates before there can be any supported
Root-My-Galaxy profile. It does not assert that the device is vulnerable
to CVE-2026-43499 or has working privilege escalation or KernelSU.

The earlier full Samsung `Image` compilation campaign is **optional
toolchain research**, not a dependency of this port. Build #10 failed
in `arch/arm64/mm/cache.o`; its provided tail does not identify the
underlying error. There is no reason to continue fixing unrelated
kernel compilation errors to perform the firmware-to-profile audit.

**Authoritative existing project evidence:**
- [HXL1 evidence manifest](../research/y2q-G986U1UESCHXL1/evidence.json)
- [Root feasibility / safe research pipeline](../research/y2q-G986U1UESCHXL1/ROOT_PAYLOAD_RESEARCH.md)
- [Audited Samsung kernel source investigation](../research/y2q-G986U1UESCHXL1/SAMSUNG_SOURCE.md)
- [Support feed selection limitations](../support/README.md)
- [KernelSU module constraints and Samsung adaptations](../kernelsu/README.md)

## October 10: first original-source GhostLock scan completed

Owner executed `tools/y2q_research_toolchain.py references` and `scan`
against the audited HXL1 Samsung source. The command completed with
`RESEARCH SCAN COMPLETE` and reported:

```text
Source heuristic: REVIEW_REQUIRED_POSSIBLE_UNFIXED_CODE_PATH
Deployable: NO; not an exploit or root validation.
```

This result follows the scan's *syntactic* checks: it detects the
presence of `current` in `remove_waiter()`, the absence of
`waiter->task` there, and a proxy-lock call in the futex source,
but does not assess all call-site semantics or prove that the exact
booted HXL1 kernel has the same implementation. The Linux CVE
advisory identifies the specific bug as using `current` when
proxy-lock rollback operates on `waiter->task`. Relevant fix:
[Linux kernel CVE-2026-43499 announcement](https://lists.openwall.net/linux-cve-announce/2026/05/21/7).

**Next read-only checkpoints (do not run a crash PoC on the phone):**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 - <<'PY'
import json
from pathlib import Path
report = json.loads(Path.home().joinpath(
    "s20-artifacts/hxl1-research/candidate.json").read_text())
for key in ("stockKernelInspection", "bootArtifactChecks", "unmetGates"):
    print("\n" + key + ":")
    print(json.dumps(report.get(key), indent=2))
PY

grep -nE '(remove_waiter|rt_mutex_start_proxy_lock)[[:space:]]*\(' \
  ~/src/samsung-y2q-hxl1-stock/kernel/locking/rtmutex.c
grep -n 'rt_mutex_start_proxy_lock' \
  ~/src/samsung-y2q-hxl1-stock/kernel/futex.c
```

Read the *full implementation* and call sites before drawing a
conclusion. The exact source file and kernel binary correlation
remain an open gate. No HXL1 payload, offsets, KernelSU module or
support-feed entry is authorized by this static finding.

---

## October 10: owner-confirmed source locations (semantic review next)

The owner shared the full `candidate.json` source-inspection summary.
It confirms the original assembled stock tree passed the 40/40 overlay
integrity check and that the scan recognized the following:

| Code | Owner-observed location |
|---|---|
| `kernel/locking/rtmutex.c`: `remove_waiter()` | line **1068** |
| `rt_mutex_start_proxy_lock()` | lines **1797–1806**, rollback calls `remove_waiter(lock, waiter)` |
| Additional `remove_waiter()` caller | line **1912** |
| `kernel/futex.c`: proxy-lock call | line **2156** |
| Other internal proxy-lock use | line **2914** |

SHA-256 of these source files respectively:
`36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9`
and
`493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`.
The scanner found `current` but no `waiter->task` reference
inside `remove_waiter()`. **This is suggestive, not a semantic
proof**: all branches, task-identity assumptions and callers must
be checked.

The [upstream CVE-2026-43499 description](https://lists.openwall.net/linux-cve-announce/2026/05/21/7)
describes proxy-lock rollback with `waiter->task != current`.
The [published Ubuntu backport](https://lists.ubuntu.com/archives/kernel-team/2026-July/169898.html)
shows the three operations requiring task identity: the task
`pi_lock`, clearing `pi_blocked_on`, and selecting the task for
priority-chain adjustment. The vendor 4.19 code may use different
names, function signatures and guards. Do **not** transplant a
5.15 patch verbatim.

**Use read-only, bounded source excerpts for the next review:**

```bash
nl -ba ~/src/samsung-y2q-hxl1-stock/kernel/locking/rtmutex.c |
  sed -n '1060,1145p;1792,1815p;1875,1920p'

nl -ba ~/src/samsung-y2q-hxl1-stock/kernel/futex.c |
  sed -n '2138,2185p'
```

Record which task owns the waiter in each call, which `pi_lock`
is held during a waiter dequeue, which task receives
`pi_blocked_on = NULL`, and which task enters
`rt_mutex_adjust_prio_chain()`. If these cannot be established,
the result stays `REVIEW_REQUIRED`.

The `bootArtifactChecks` object was **empty** in the owner's first
scan: original firmware hashes are in `evidence.json`, but the
scan did not independently verify original `boot.img` or
`kernel.bin` bytes. Do that later from the original
extracted files, not a reconstructed `Image`.
No HXL1 CVE/root verification, KernelSU loader or support-feed
publication follows from this result.

---

## October 10: source-level GhostLock task identity error confirmed

The owner provided bounded, numbered, unmodified source excerpts from
`kernel/locking/rtmutex.c` and `kernel/futex.c`. This advances the source
assessment beyond a heuristic: **the audited reconstructed HXL1 source
contains the specific incorrect task identity handling described by
CVE-2026-43499.**

| Upstream CVE error | Actual HXL1 source evidence |
|---|---|
| Dequeue without the waiter's task `pi_lock` | `rtmutex.c:1077–1080` locks `current->pi_lock` and dequeues `waiter` |
| Waiter's `pi_blocked_on` state not cleared | `rtmutex.c:1079` clears `current->pi_blocked_on` instead |
| Wrong priority-chain task | `rtmutex.c:1115–1116` passes `current` as final `rt_mutex_adjust_prio_chain()` argument |
| Proxied target differs from caller | `rtmutex.c:1797–1806` accepts a separate `task`, calls proxy lock, then `remove_waiter(lock, waiter)` on rollback; `futex.c:2156–2158` passes `this->rt_waiter` and `this->task` |

Source SHA-256 recorded with the previous scan:
`rtmutex.c` = `36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9`;
`futex.c` = `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`.

The [official Linux kernel advisory](https://lists.openwall.net/linux-cve-announce/2026/05/21/7)
explains precisely these three mistakes. `rt_mutex_cleanup_proxy_lock()`
at `rtmutex.c:1889–1912` is a separate path: its caller and
`try_to_take_rt_mutex(lock, current, waiter)` use the current task.
That path must not be conflated with proxy-start rollback.

**What is verified:** the vulnerability's source-level code pattern and
the cross-task proxy-lock caller are both present in the reconstructed
Samsung source supplied by the owner.

**What is NOT verified:** byte-for-byte equivalence between the original
extracted firmware kernel and the booted kernel; the code path's
reproducible exploitation on device; arbitrary kernel memory access;
KernelSU load; root; safety under Samsung RKP/KDP/DEFEX. The existing
`bootArtifactChecks` object is empty because no original image paths
were passed to the initial scan. Keep `vulnerabilityVerified=false`
as a *device-level* gate and the research candidate outside the feed.

### Next safe gate — original kernel binary provenance

Locate the **original** extracted `boot.img` and `kernel.bin` on the
WSL host and verify their recorded SHA-256s. Do not use the
Clang18-rebuilt `Image`. The expected digests are:

```text
boot.img   bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8
kernel.bin ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123
```

With those verified, inspect the binary format and whether
read-only symbol recovery or BTF is possible. The source-level
bug does not require more full-kernel compilation. Do not run
kernel-panic or instability-oriented proof-of-concept code
on the physical phone simply to close this evidence gate.

---

## October 10: original HXL1 firmware Image cryptographically verified

The owner supplied the following **real WSL2 file checks**, against
the original Samsung firmware extraction (not the Clang18 rebuild):

```text
/home/main/s20-artifacts/boot.img
bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8

/home/main/s20-artifacts/kernel.bin
ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123

file kernel.bin:
Linux kernel ARM64 boot executable Image, little-endian, 4K pages
```

Both hashes **match the already recorded official firmware extraction
artifacts** in `evidence.json`. This closes the *file integrity and raw
ARM64 format recognition* checkpoints. It does **not** establish
byte-for-byte correspondence between original extracted kernel and
the image currently executing in RAM.

### Next: read-only stock ARM64 Image header and tool availability

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 - <<'PY'
from pathlib import Path
import struct
p = Path.home() / "s20-artifacts/kernel.bin"
with p.open("rb") as fh:
    header = fh.read(64)
if len(header) != 64 or header[0x38:0x3c] != b"ARM\x64":
    raise SystemExit("STOP: invalid or unsupported ARM64 Image header")
text_offset, image_size, flags = struct.unpack_from("<QQQ", header, 8)
print("Image:", p)
print("file bytes:", p.stat().st_size)
print(f"magic: {header[0x38:0x3c].hex()}")
print(f"text_offset: 0x{text_offset:x}")
print(f"image_size: 0x{image_size:x}")
print(f"flags: 0x{flags:x}")
PY
command -v vmlinux-to-elf || true
command -v llvm-nm || true
command -v bpftool || true
```

Use `vmlinux-to-elf` only on the confirmed original ARM64
`kernel.bin` if that utility is installed. Extracted symbols may
be partial/inaccurate; any names or addresses must be verified
against the actual instruction bytes and source. Do not use
generated Clang18 objects as stand-ins for firmware symbols.

**BTF is still unknown.** The S24 FE's BTF location and structure
offsets cannot be copied here. Search for, then validate the complete
little-endian BTF header and section bounds; an absence of candidates
in a raw Image is not proof that this build never generated BTF.
Do not run a CVE PoC or module loader at this stage.

---

## October 10: original ARM64 Image header and WSL tooling

The owner checked the previously SHA-256-verified original
`/home/main/s20-artifacts/kernel.bin` header:

| Field | Observed |
|---|---|
| Physical file length | `51,957,772` bytes |
| ARM64 magic | `ARM\\x64` (passed validation) |
| `text_offset` | `0x80000` |
| `image_size` | `0x433b000` |
| `flags` | `0xa` |
| `llvm-nm` | `/usr/bin/llvm-nm` |
| `vmlinux-to-elf` | Not installed |
| `bpftool` | Not installed |

The kernel [ARM64 boot documentation](https://kernel.org/doc/html/v6.16/arch/arm64/booting.html)
defines `image_size` as an **effective memory reservation**.
Its larger value does not prove disk image corruption. `0x80000`
is an image **offset**, not the absolute Qualcomm physical load address.

### Next WSL commands: symbol recovery on original kernel only

Use an isolated Python CLI installer (do not install using
`sudo pip3`):

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
export PATH="$HOME/.local/bin:$PATH"
pipx install vmlinux-to-elf

mkdir -p ~/s20-artifacts/hxl1-research
vmlinux-to-elf ~/s20-artifacts/kernel.bin \
  ~/s20-artifacts/hxl1-research/vmlinux-stock.elf

file ~/s20-artifacts/hxl1-research/vmlinux-stock.elf
llvm-nm -n ~/s20-artifacts/hxl1-research/vmlinux-stock.elf \
  > ~/s20-artifacts/hxl1-research/vmlinux-stock.nm
wc -l ~/s20-artifacts/hxl1-research/vmlinux-stock.nm
```

This runs **off-device**. A recovered ELF can be incomplete or
incorrect; symbol names/offsets remain unverified until crosschecked
with the actual Image and Samsung source. If extraction fails, retain
the exact error; do not fabricate symbols or use the Clang18 build
as the stock image.

Before installing a BTF tool, check the original device config:

```bash
gzip -dc ~/s20-artifacts/config.gz |
  grep -E '^(CONFIG_DEBUG_INFO_BTF|# CONFIG_DEBUG_INFO_BTF)' || true
```

Ubuntu 24.04 provides `bpftool` via the virtual
`linux-tools-common` package, not directly via
`apt install bpftool`. On WSL2, the common package may
install **only a wrapper** expecting a matching host kernel
tool that Ubuntu cannot supply. If embedded BTF is actually
identified and passes header/bounds checks, install:

```bash
sudo apt install -y linux-tools-common linux-tools-generic
find /usr/lib/linux-tools -type f -name bpftool -print
```

Run an actual `/usr/lib/linux-tools/<version>/bpftool` binary
directly when `bpftool` reports a WSL kernel mismatch.
BTF still has **not** been established for HXL1.
No installation or exploitation commands for the S20+ are part of
this stage.

---

## October 10: WSL2 symbol tool installation blocker and BTF configuration check

The owner ran the exact `CONFIG_DEBUG_INFO_BTF` grep against
the retained original `config.gz` and got **no matching line**.
That is **not** proof of an embedded BTF blob, nor by itself
proof that BTF is absent: defer BTF parsing until the
original kernel binary is independently inspected. The
original source image remains available and was previously
hash-verified.

Ubuntu Noble `pipx install vmlinux-to-elf` failed **before
installation**, while building the transitive dependency
`minilzo`. The actual compiler error was:

```text
lzomodule.c:2:10: fatal error: Python.h: No such file or directory
```

This requires Ubuntu Python 3.12 development headers, not a
Samsung kernel change. Next, on WSL2:

```bash
sudo apt install -y python3.12-dev build-essential liblzo2-dev
test -f /usr/include/python3.12/Python.h
python3-config --includes
pipx install vmlinux-to-elf
command -v vmlinux-to-elf
```

Ubuntu's `libpython3.12-dev` contains
`/usr/include/python3.12/Python.h`; `python3.12-dev`
depends on the appropriate development components.
This should fix the **reported missing-header error**,
but a subsequent Python-API or LZO compatibility error
requires its own log rather than an unsupported assumption.
Keep installations inside `pipx` and do not use
`sudo pip`.

Once the command exists, run symbol recovery on the
**original raw** HXL1 `kernel.bin` as detailed above.
Also inspect original config's relevant keys:

```bash
gzip -dc ~/s20-artifacts/config.gz |
  grep -E '^CONFIG_(KALLSYMS|KALLSYMS_ALL|DEBUG_INFO)=' || true
```

The kernel's source-level CVE logic has been established,
but exact running-binary equivalence, successful symbol
recovery, BTF, root and KernelSU remain unverified.

---

## October 10: offline reconstruction of a symbolized *stock* kernel ELF

The owner successfully ran `vmlinux-to-elf` against the exact,
previously SHA-256-verified original
`/home/main/s20-artifacts/kernel.bin`. It recognized:

- Full banner: `Linux version 4.19.113-27095354`, built using
  `clang 10.0.6 for Android NDK`; architecture `aarch64`.
- Embedded `kallsyms_names` at raw offset `0x01f0ea00`,
  reporting **145,434** symbols; GNU-style
  `llvm-nm -n` output has **145,433** lines.
- Relocation table `0x2695260–0x29da650`,
  with **142,890** entries, of which **142,860** were applied.
- Guessed static virtual base `0xffffff8008080000`.
- Recovered file `hxl1-research/vmlinux-stock.elf` is
  ARM64 ELF64 LSB, statically linked and **not stripped**.

The decoder also warned **0% negative** and
**100% apparently absolute** kallsyms offsets.
Its own documentation explains that the base address and
kallsyms representation can require overriding or independent
validation. These warnings are **not a failed extraction**,
but neither a guessed base nor the reported function addresses
can be considered verified until instruction-level checks pass.
No reconstructed ELF is identical to the original raw
`kernel.bin`.

### Next: verify virtual layout and relevant symbol entries

The following commands **only read local evidence**:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

ELF="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.elf"
NM="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm"

sha256sum "$ELF"
readelf -hW "$ELF" | grep -E 'Class:|Data:|Type:|Machine:|Entry point'
readelf -lW "$ELF" | head -n 45

grep -E ' (_text|_stext|start_kernel|remove_waiter|__rt_mutex_start_proxy_lock|rt_mutex_start_proxy_lock)

| Original section | HXL1 status | What changes for y2q / 4.19 |
|---|---|---|
| 1. Exact firmware | **Complete** | Use hardware-confirmed US `SM-G986U1`/HXL1, not S24 FE, and leave unknown CSC/CP fields unknown |
| 2. Firmware/kernel extraction | **Complete: hashes and boot header; binary/source equivalence not established** | Boot header **v2**, not v4; use retained `kernel.bin` from the original `boot.img`, verify bytes and compression before treating it as a raw ARM64 Image |
| 3. Symbols and BTF | **Pending** | Recover only from the exact stock extracted kernel; BTF presence, recovered ELF, symbols and layouts are not yet established |
| 4. Bootloader/physical address | **Pending** | S20+ Qualcomm boot chain, not S24 FE BL assumptions; no HXL1 physical base or KASLR slide asserted |
| 5. Runtime / slide validation | **Pending** | Observed trace event ID **72** is *not* stable or accepted as an exploit constant; derive/verify everything for 4.19 independently |
| 6. Native target | **Research-only identity probe exists** | Do not invent `src/targets/y2q-G986U1UESCHXL1/target.h` offsets or compile/register a working exploit |
| 7. KernelSU | **Blocked** | Linux 4.19 KMI, Samsung RKP/KDP/DEFEX, forced module signatures and disabled kprobes need independent compatibility design/validation |
| 8. Feed publication | **Prohibited** | `targets-v3.json` uses model plus *truncated* numeric kernel version; that is insufficient for an experimental exact-firmware target |
| 9. Cleanup | **Deferred** | Retain original verified inputs, logs, hashes and research reports until evidence review closes |

## 1. Freeze exact firmware identity (PORTING.md `1) — COMPLETE

Read-only device identity probe was executed on the physical S20+
through ADB shell and returned `FIRMWARE_IDENTITY_MATCH`, **uid 2000**:

| Field | Observed exact value |
|---|---|
| Model | `SM-G986U1` |
| Device / product | `y2q` / `y2quew` |
| Firmware / bootloader | `G986U1UESCHXL1` |
| Display build | `TP1A.220624.014.G986U1UESCHXL1` |
| Fingerprint | `samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys` |
| Android / SDK / ABI | `13` / `33` / `arm64-v8a` |
| Complete `uname -r` | `4.19.113-27095354` |
| Kernel toolchain reported by `/proc/version` | `clang 10.0.6 for Android NDK` |
| Security patch | `2025-01-01` |
| Page size | `4096` |
| Verified boot state | flash locked `1`; vbmeta `locked` |
| Execution context | Shizuku / ADB shell `uid=2000`, SELinux enforcing |
| Region, CSC and CP | **Not confirmed by current evidence**; do not invent or substitute S24 values |

Use the **complete** `uname -r`, fingerprint, build and firmware
identity in research candidate checks. A kernel version `4.19.113`
alone does not identify this Samsung patch set.

Recheck the **existing** non-exploit identity probe if anything
about the firmware changes:

```bash
cd ~/src/Root-My-Galaxy-Payloads
# Android NDK is used ONLY to compile the user-space identity probe.
ANDROID_NDK_HOME=/path/to/installed/android-ndk \
  bash research/y2q-G986U1UESCHXL1/build_probe.sh
```

The probe's previously recorded successful hardware execution proves
only identity and ordinary native-code execution as the shell user.

## 2. Keep the exact firmware / kernel artifact chain (PORTING.md `2) — EXTRACTED

The original Samsung `boot.img` has **Android boot image header
version 2**, board name `SRPSH29C012`, not the S24 reference's
version-4 layout. Do **not** hard-code the S24 kernel start at
`0x1000`, its kernel size, or its `vendor_boot.img` assumptions.

| Existing HXL1 artifact | Bytes | SHA-256 |
|---|---:|---|
| `boot.img.lz4` | 25,597,493 | `02099ccbfb423292b631f228b8d3163b9a601f4a058360a4bca93f71f8e50a78` |
| `boot.img` | 67,108,864 | `bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8` |
| extracted `kernel.bin` | 51,957,772 | `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` |
| `config.gz` | 42,754 | `1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd` |
| `ramdisk.img` | 724,388 | `86b00ab1f20206ceedcc574423ef11417927aa1f773408ec2c2af4a855ea7586` |
| `dtb.img` | 1,580,275 | `a6104cdba11e0cd3d6ddaba6819098ab01f0dc0e8e7fd333137c88ad07d9d0ce` |

These hashes were recorded from the owner's original HXL1
extraction; a later off-device `Image` is **not equivalent evidence**.
Before symbol work, check the retained originals and determine if
`kernel.bin` requires decompression to obtain the raw ARM64 Linux
Image. The manifest does **not** establish whether an ELF symbol
recovery has succeeded or whether embedded BTF exists.

For ordinary read-only byte verification, adapt the paths to the
real original extracted files, never the rebuilt experimental output:

```bash
sha256sum /path/to/original/boot.img \
          /path/to/original/kernel.bin \
          /path/to/original/config.gz
file /path/to/original/kernel.bin
```

**Source provenance:** Samsung's `SM-G986U.zip` wrapper contained
11 selected layers: base kernel, U1 DTS and nine chronological
firmware overlays **through HXL1**. The auditing process verified
40 final overlay file hashes. The stock reconstructed source is:

```text
~/src/samsung-y2q-hxl1-stock
```

It matches the running 4.19.113 kernel *configuration* closely,
but full binary equivalence to the handset's stock kernel remains
unproven. The Clang 18 two-/three-patch source copies are **not**
the source of truth for this port.

## 3. Symbols / structures / CVE applicability (PORTING.md `3) — PENDING

The baseline PORTING document uses an exact recovered, symbolized
S24 kernel `vmlinux.elf` and BTF to derive function offsets and
structure layouts. **Do not copy any of those values**. None of
the following have been reported as verified against the extracted
S20+ HXL1 kernel: raw ARM64 Image header, symbolized `vmlinux.elf`,
kernel BTF, target `Module.symvers` or disassembly-validated
structure layout.

Relevant **observed** HXL1 configuration:

```text
CONFIG_ARCH_QCOM=y
CONFIG_ARCH_KONA=y
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_RT_MUTEXES=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KPROBES=n
CONFIG_MODULES=y
CONFIG_MODVERSIONS=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_UH_RKP=y
CONFIG_KDP_CRED=y
CONFIG_KDP_NS=y
CONFIG_SECURITY_DEFEX=y
```

This means FUTEX_PI exists in the reported config; it does **not**
prove the CVE applies, is reachable from this device, or can be
exploited. `CONFIG_KALLSYMS_ALL=y` also does **not** imply
`/proc/kallsyms` is readable under enforcing SELinux; owner
diagnostics found it inaccessible to the shell context.

**First action (already implemented, no kernel rebuild):**
run the guarded, read-only source-applicability scan against
the original audited kernel tree. Its control-flow classification
is *heuristic*, not a vulnerability confirmation.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
mkdir -p ~/s20-artifacts/hxl1-research

python3 tools/y2q_research_toolchain.py scan \
  --evidence research/y2q-G986U1UESCHXL1/evidence.json \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --stock-source ~/src/samsung-y2q-hxl1-stock \
  --output ~/s20-artifacts/hxl1-research/candidate.json
```

Pass criteria for this stage are **documented source provenance,
the complete `rtmutex`/`futex` code-path review, and exact binary
correlation**. A static scan naming a possibly unfixed function
is only a *review finding*; it is not a go-ahead for a payload.

## 4. Confirm load address and bootloader (PORTING.md `4) — PENDING

The S24 procedure examines the correct device's bootloader to
establish physical base and kernel entry. HXL1 has neither of
those validated yet. For this Qualcomm/Samsung boot chain,
inspect the **matching original BL archive** and its actual boot
handoff implementation; do not reuse S24 FE or S24 Ultra load
addresses, ARM64 text offsets, memory-region assumptions,
or `KIMAGE_TEXT_BASE`. Cross-check the Image header and its
corresponding BL provenance first.

The S20+ locked bootloader is an important **deployment
restriction**. Deriving a load address does not bypass boot
verification or imply an unsigned Image can be booted.

## 5. Runtime validation gates (PORTING.md `5) — PENDING

The reference `SLIDE_TRACEFS_EVENT_ID`, worker return offset,
`SLIDE_PSELECT_WORD_SHIFT`, physical-page fingerprints, and
kernel/object layout values are **per firmware** and may not
even be derived in the same way on Android 4.19.

The existing Shizuku/ADB diagnostic observed a trace event ID
of `72`, but **not a stable proven per-boot value**. It must
not be reused as an exploit parameter. Kernel symbols were not
accessible through `/proc/kallsyms` in this shell context.

Keep all high-risk functionality disabled while reviewing
potential runtime dependencies. Document shell versus app-domain
permissions separately: an observation made with Shizuku's
authorized shell bridge does not prove an app-domain route
will work.

## 6. Target/package development (PORTING.md `6) — RESEARCH ONLY

The current repository already provides:

- `tools/assess_y2q_root_candidate.py`: static source/evidence triage;
- `tools/y2q_research_toolchain.py`: `references`, `scan`,
  `build-probe` and `bundle` commands;
- `research/y2q-G986U1UESCHXL1/identity_probe.c`:
  Android ARM64 executable, hardware-verified as ordinary shell;
- `research/y2q-G986U1UESCHXL1/diagnostic_payload.c`:
  read-only, fingerprint-locked shared library, not a root exploit.

Use a standard Android NDK (API 33 / ARM64) for the diagnostic
shared library; the Samsung Clang18/`Image` toolchain is not
required:

```bash
export ANDROID_NDK_HOME=/path/to/installed/android-ndk

python3 tools/y2q_research_toolchain.py build-probe \
  --scan-report ~/s20-artifacts/hxl1-research/candidate.json \
  --ndk "$ANDROID_NDK_HOME" \
  --output ~/s20-artifacts/hxl1-research/y2q-G986U1UESCHXL1-identity-diagnostic.so \
  --manifest ~/s20-artifacts/hxl1-research/binary.json

python3 tools/y2q_research_toolchain.py bundle \
  --scan-report ~/s20-artifacts/hxl1-research/candidate.json \
  --library ~/s20-artifacts/hxl1-research/y2q-G986U1UESCHXL1-identity-diagnostic.so \
  --manifest ~/s20-artifacts/hxl1-research/binary.json \
  --output ~/s20-artifacts/hxl1-research/y2q-HXL1-diagnostics.zip
```

The packaged `.so` is **not** an exploit or KernelSU loader,
and is not an installable rooting payload. The above toolchain
refuses to claim a working root path. Do not add unknown
addresses or placeholder exploit values to a production
`src/targets/.../target.h`.

## 7. KernelSU and Samsung 4.19 compatibility (PORTING.md `7) — BLOCKED

`kernelsu/README.md` documents working versions for other
kernel families (5.10, 5.15, 6.1 and 6.6). None has been
proven usable on this `4.19.113-27095354` kernel, and a
module compiled for another KMI is not interchangeable.

**Critical differences to assess independently:**
- `CONFIG_MODULE_SIG_FORCE=y`; a conventional module
  install requires an accepted signature. A documented
  experimental late-load implementation elsewhere does
  **not** establish this device's loading path.
- `CONFIG_KPROBES=n` removes a common KernelSU hooking
  mechanism relied on by other device adaptations.
- RKP, KDP and DEFEX may constrain credential handling,
  kernel text modification and module initialization.
- Confirm target `CONFIG_MODULE_FORCE_LOAD`,
  `CONFIG_TRIM_UNUSED_KSYMS`, `Module.symvers`,
  `vermagic`, relevant exports and module architecture
  from **this** stock config/source before deciding
  whether a module implementation is even feasible.

No `kernelsu.ko`, `ksud` binary, module load or root
credential transition is verified for HXL1. A complete
Samsung `Image` is not a substitute for any of these gates.

## 8. App/feed integration (PORTING.md `8) — BLOCKED

`support/targets-v3.json` currently matches primarily
`Build.MODEL` and the leading three numeric components
of `uname -r`. That lookup is too broad to authorize
an unverified 4.19.113 root implementation for HXL1.
The full-build check must occur **before any executable
could run**, and the research tooling must reject other
versions/models and fail closed.

Do **not** publish a `y2q` entry to v2 or v3,
copy in a generic KMI or CVE payload from a different
device, or expose an active Root action for HXL1
merely because the read-only diagnostic returns
`FIRMWARE_IDENTITY_MATCH`.

Research document location is intentionally outside the
production `artifacts/` and `src/targets/` namespaces.

## 9. Retention, rollback, and readiness (PORTING.md `9)

Keep the immutable `boot.img`, `kernel.bin`,
`config.gz`, exact SHA-256s, source-audit reports,
full build/source provenance, safe shell diagnostics,
and candidate JSON while the port remains incomplete.
Do not discard forensic inputs or overwrite historical
build logs. A verified-boot / recovery plan is required
before higher-risk hardware tests.

### Recommended development order

1. **Now:** run `tools/y2q_research_toolchain.py scan`,
   inspect `candidate.json` and manually evaluate
   possible Samsung-specific fixes/backports in 4.19;
   retain uncertainty if code diverges.
2. Verify the exact **stock extracted kernel** format,
   recover any available symbols, and establish a
   source/binary link. Establish if BTF is present;
   do not assume it.
3. Independently document the HXL1 bootloader/load chain,
   while preserving the locked verification state.
4. Review runtime permission limitations and
   Linux 4.19-specific implementation constraints,
   with no production exploit or module installed.
5. Only after independent, repeatable, authorized
   hardware evidence should module/runtime implementation
   and app integration become eligible for review.
6. Publish **nothing** until full firmware-specific
   compatibility, recovery, and access checks pass.

### Explicit acceptance gates

| Gate | Required evidence | Present status |
|---|---|---|
| Exact device/firmware identification | Full fingerprint, build, release, non-root probe | **PASS** |
| Genuine original firmware input | Recorded hashes for extracted AP data | **PASS for extracted file hashes**; booted-binary equivalence not asserted |
| Reconstructed stock source/config | Samsung archive provenance; 40 hashes; config comparisons | **PASS as audited reconstructed source**; binary identity open |
| CVE-2026-43499 code applicability | Reviewed Samsung code + fix history + exact-binary correlation | **OPEN** |
| Symbol and struct provenance | Actual extracted Image + verified ELF/BTF/layout data | **OPEN** |
| Bootloader/layout provenance | Exact HXL1 boot chain evidence | **OPEN** |
| Runtime exploit reliability/safety | Authorized, reproducible, independent hardware validation | **OPEN** |
| KernelSU 4.19 loading/behavior | Exact KMI, mandatory security constraints, clean verified run | **OPEN** |
| Safe production support matching | Reject non-HXL1/mismatched fingerprint and release | **OPEN** |
| Reboot/recovery readiness | Independently tested recovery and rollback plan | **OPEN** |

**Conclusion:** Porting `PORTING.md` to HXL1 starts with **stock
kernel evidence and device-specific feasibility**, not with making
Clang18 compile Samsung's full Linux `Image`. The user-space
diagnostic and static source review can proceed now; a working
root payload and KernelSU installation cannot be asserted.
 "$NM" || true

llvm-objdump -d --disassemble-symbols=remove_waiter "$ELF" |
  head -n 90

llvm-objdump -d --disassemble-symbols=rt_mutex_start_proxy_lock "$ELF" |
  head -n 90
```

Inspect `readelf`'s load mapping and the extracted symbol type
and address before using any instruction addresses; local
`remove_waiter` might be absent due to compilation or
optimization. Do not substitute offsets from another phone.
The `0x80000` ARM64 Image `text_offset` is a boot placement
offset, while `0xffffff8008080000` is the ELF tool's
provisional virtual base; they have **different meanings**.
Neither is a measured runtime/KASLR base.

No firmware-specific exploit constants, memory writes, credential
changes, KernelSU loads or support-feed entries have been
confirmed or authorized by the symbol recovery alone.
Continue with the separate BTF presence check and original
instruction/source correlation.

---

## Adaptation map from PORTING.md

| Original section | HXL1 status | What changes for y2q / 4.19 |
|---|---|---|
| 1. Exact firmware | **Complete** | Use hardware-confirmed US `SM-G986U1`/HXL1, not S24 FE, and leave unknown CSC/CP fields unknown |
| 2. Firmware/kernel extraction | **Complete: hashes and boot header; binary/source equivalence not established** | Boot header **v2**, not v4; use retained `kernel.bin` from the original `boot.img`, verify bytes and compression before treating it as a raw ARM64 Image |
| 3. Symbols and BTF | **Pending** | Recover only from the exact stock extracted kernel; BTF presence, recovered ELF, symbols and layouts are not yet established |
| 4. Bootloader/physical address | **Pending** | S20+ Qualcomm boot chain, not S24 FE BL assumptions; no HXL1 physical base or KASLR slide asserted |
| 5. Runtime / slide validation | **Pending** | Observed trace event ID **72** is *not* stable or accepted as an exploit constant; derive/verify everything for 4.19 independently |
| 6. Native target | **Research-only identity probe exists** | Do not invent `src/targets/y2q-G986U1UESCHXL1/target.h` offsets or compile/register a working exploit |
| 7. KernelSU | **Blocked** | Linux 4.19 KMI, Samsung RKP/KDP/DEFEX, forced module signatures and disabled kprobes need independent compatibility design/validation |
| 8. Feed publication | **Prohibited** | `targets-v3.json` uses model plus *truncated* numeric kernel version; that is insufficient for an experimental exact-firmware target |
| 9. Cleanup | **Deferred** | Retain original verified inputs, logs, hashes and research reports until evidence review closes |

## 1. Freeze exact firmware identity (PORTING.md `1) — COMPLETE

Read-only device identity probe was executed on the physical S20+
through ADB shell and returned `FIRMWARE_IDENTITY_MATCH`, **uid 2000**:

| Field | Observed exact value |
|---|---|
| Model | `SM-G986U1` |
| Device / product | `y2q` / `y2quew` |
| Firmware / bootloader | `G986U1UESCHXL1` |
| Display build | `TP1A.220624.014.G986U1UESCHXL1` |
| Fingerprint | `samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys` |
| Android / SDK / ABI | `13` / `33` / `arm64-v8a` |
| Complete `uname -r` | `4.19.113-27095354` |
| Kernel toolchain reported by `/proc/version` | `clang 10.0.6 for Android NDK` |
| Security patch | `2025-01-01` |
| Page size | `4096` |
| Verified boot state | flash locked `1`; vbmeta `locked` |
| Execution context | Shizuku / ADB shell `uid=2000`, SELinux enforcing |
| Region, CSC and CP | **Not confirmed by current evidence**; do not invent or substitute S24 values |

Use the **complete** `uname -r`, fingerprint, build and firmware
identity in research candidate checks. A kernel version `4.19.113`
alone does not identify this Samsung patch set.

Recheck the **existing** non-exploit identity probe if anything
about the firmware changes:

```bash
cd ~/src/Root-My-Galaxy-Payloads
# Android NDK is used ONLY to compile the user-space identity probe.
ANDROID_NDK_HOME=/path/to/installed/android-ndk \
  bash research/y2q-G986U1UESCHXL1/build_probe.sh
```

The probe's previously recorded successful hardware execution proves
only identity and ordinary native-code execution as the shell user.

## 2. Keep the exact firmware / kernel artifact chain (PORTING.md `2) — EXTRACTED

The original Samsung `boot.img` has **Android boot image header
version 2**, board name `SRPSH29C012`, not the S24 reference's
version-4 layout. Do **not** hard-code the S24 kernel start at
`0x1000`, its kernel size, or its `vendor_boot.img` assumptions.

| Existing HXL1 artifact | Bytes | SHA-256 |
|---|---:|---|
| `boot.img.lz4` | 25,597,493 | `02099ccbfb423292b631f228b8d3163b9a601f4a058360a4bca93f71f8e50a78` |
| `boot.img` | 67,108,864 | `bd8987c28ef0b9fdb56ad3e82ce3b45929c5e53717525769e5625dd1e17f7dc8` |
| extracted `kernel.bin` | 51,957,772 | `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` |
| `config.gz` | 42,754 | `1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd` |
| `ramdisk.img` | 724,388 | `86b00ab1f20206ceedcc574423ef11417927aa1f773408ec2c2af4a855ea7586` |
| `dtb.img` | 1,580,275 | `a6104cdba11e0cd3d6ddaba6819098ab01f0dc0e8e7fd333137c88ad07d9d0ce` |

These hashes were recorded from the owner's original HXL1
extraction; a later off-device `Image` is **not equivalent evidence**.
Before symbol work, check the retained originals and determine if
`kernel.bin` requires decompression to obtain the raw ARM64 Linux
Image. The manifest does **not** establish whether an ELF symbol
recovery has succeeded or whether embedded BTF exists.

For ordinary read-only byte verification, adapt the paths to the
real original extracted files, never the rebuilt experimental output:

```bash
sha256sum /path/to/original/boot.img \
          /path/to/original/kernel.bin \
          /path/to/original/config.gz
file /path/to/original/kernel.bin
```

**Source provenance:** Samsung's `SM-G986U.zip` wrapper contained
11 selected layers: base kernel, U1 DTS and nine chronological
firmware overlays **through HXL1**. The auditing process verified
40 final overlay file hashes. The stock reconstructed source is:

```text
~/src/samsung-y2q-hxl1-stock
```

It matches the running 4.19.113 kernel *configuration* closely,
but full binary equivalence to the handset's stock kernel remains
unproven. The Clang 18 two-/three-patch source copies are **not**
the source of truth for this port.

## 3. Symbols / structures / CVE applicability (PORTING.md `3) — PENDING

The baseline PORTING document uses an exact recovered, symbolized
S24 kernel `vmlinux.elf` and BTF to derive function offsets and
structure layouts. **Do not copy any of those values**. None of
the following have been reported as verified against the extracted
S20+ HXL1 kernel: raw ARM64 Image header, symbolized `vmlinux.elf`,
kernel BTF, target `Module.symvers` or disassembly-validated
structure layout.

Relevant **observed** HXL1 configuration:

```text
CONFIG_ARCH_QCOM=y
CONFIG_ARCH_KONA=y
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_RT_MUTEXES=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KPROBES=n
CONFIG_MODULES=y
CONFIG_MODVERSIONS=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_UH_RKP=y
CONFIG_KDP_CRED=y
CONFIG_KDP_NS=y
CONFIG_SECURITY_DEFEX=y
```

This means FUTEX_PI exists in the reported config; it does **not**
prove the CVE applies, is reachable from this device, or can be
exploited. `CONFIG_KALLSYMS_ALL=y` also does **not** imply
`/proc/kallsyms` is readable under enforcing SELinux; owner
diagnostics found it inaccessible to the shell context.

**First action (already implemented, no kernel rebuild):**
run the guarded, read-only source-applicability scan against
the original audited kernel tree. Its control-flow classification
is *heuristic*, not a vulnerability confirmation.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
mkdir -p ~/s20-artifacts/hxl1-research

python3 tools/y2q_research_toolchain.py scan \
  --evidence research/y2q-G986U1UESCHXL1/evidence.json \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --stock-source ~/src/samsung-y2q-hxl1-stock \
  --output ~/s20-artifacts/hxl1-research/candidate.json
```

Pass criteria for this stage are **documented source provenance,
the complete `rtmutex`/`futex` code-path review, and exact binary
correlation**. A static scan naming a possibly unfixed function
is only a *review finding*; it is not a go-ahead for a payload.

## 4. Confirm load address and bootloader (PORTING.md `4) — PENDING

The S24 procedure examines the correct device's bootloader to
establish physical base and kernel entry. HXL1 has neither of
those validated yet. For this Qualcomm/Samsung boot chain,
inspect the **matching original BL archive** and its actual boot
handoff implementation; do not reuse S24 FE or S24 Ultra load
addresses, ARM64 text offsets, memory-region assumptions,
or `KIMAGE_TEXT_BASE`. Cross-check the Image header and its
corresponding BL provenance first.

The S20+ locked bootloader is an important **deployment
restriction**. Deriving a load address does not bypass boot
verification or imply an unsigned Image can be booted.

## 5. Runtime validation gates (PORTING.md `5) — PENDING

The reference `SLIDE_TRACEFS_EVENT_ID`, worker return offset,
`SLIDE_PSELECT_WORD_SHIFT`, physical-page fingerprints, and
kernel/object layout values are **per firmware** and may not
even be derived in the same way on Android 4.19.

The existing Shizuku/ADB diagnostic observed a trace event ID
of `72`, but **not a stable proven per-boot value**. It must
not be reused as an exploit parameter. Kernel symbols were not
accessible through `/proc/kallsyms` in this shell context.

Keep all high-risk functionality disabled while reviewing
potential runtime dependencies. Document shell versus app-domain
permissions separately: an observation made with Shizuku's
authorized shell bridge does not prove an app-domain route
will work.

## 6. Target/package development (PORTING.md `6) — RESEARCH ONLY

The current repository already provides:

- `tools/assess_y2q_root_candidate.py`: static source/evidence triage;
- `tools/y2q_research_toolchain.py`: `references`, `scan`,
  `build-probe` and `bundle` commands;
- `research/y2q-G986U1UESCHXL1/identity_probe.c`:
  Android ARM64 executable, hardware-verified as ordinary shell;
- `research/y2q-G986U1UESCHXL1/diagnostic_payload.c`:
  read-only, fingerprint-locked shared library, not a root exploit.

Use a standard Android NDK (API 33 / ARM64) for the diagnostic
shared library; the Samsung Clang18/`Image` toolchain is not
required:

```bash
export ANDROID_NDK_HOME=/path/to/installed/android-ndk

python3 tools/y2q_research_toolchain.py build-probe \
  --scan-report ~/s20-artifacts/hxl1-research/candidate.json \
  --ndk "$ANDROID_NDK_HOME" \
  --output ~/s20-artifacts/hxl1-research/y2q-G986U1UESCHXL1-identity-diagnostic.so \
  --manifest ~/s20-artifacts/hxl1-research/binary.json

python3 tools/y2q_research_toolchain.py bundle \
  --scan-report ~/s20-artifacts/hxl1-research/candidate.json \
  --library ~/s20-artifacts/hxl1-research/y2q-G986U1UESCHXL1-identity-diagnostic.so \
  --manifest ~/s20-artifacts/hxl1-research/binary.json \
  --output ~/s20-artifacts/hxl1-research/y2q-HXL1-diagnostics.zip
```

The packaged `.so` is **not** an exploit or KernelSU loader,
and is not an installable rooting payload. The above toolchain
refuses to claim a working root path. Do not add unknown
addresses or placeholder exploit values to a production
`src/targets/.../target.h`.

## 7. KernelSU and Samsung 4.19 compatibility (PORTING.md `7) — BLOCKED

`kernelsu/README.md` documents working versions for other
kernel families (5.10, 5.15, 6.1 and 6.6). None has been
proven usable on this `4.19.113-27095354` kernel, and a
module compiled for another KMI is not interchangeable.

**Critical differences to assess independently:**
- `CONFIG_MODULE_SIG_FORCE=y`; a conventional module
  install requires an accepted signature. A documented
  experimental late-load implementation elsewhere does
  **not** establish this device's loading path.
- `CONFIG_KPROBES=n` removes a common KernelSU hooking
  mechanism relied on by other device adaptations.
- RKP, KDP and DEFEX may constrain credential handling,
  kernel text modification and module initialization.
- Confirm target `CONFIG_MODULE_FORCE_LOAD`,
  `CONFIG_TRIM_UNUSED_KSYMS`, `Module.symvers`,
  `vermagic`, relevant exports and module architecture
  from **this** stock config/source before deciding
  whether a module implementation is even feasible.

No `kernelsu.ko`, `ksud` binary, module load or root
credential transition is verified for HXL1. A complete
Samsung `Image` is not a substitute for any of these gates.

## 8. App/feed integration (PORTING.md `8) — BLOCKED

`support/targets-v3.json` currently matches primarily
`Build.MODEL` and the leading three numeric components
of `uname -r`. That lookup is too broad to authorize
an unverified 4.19.113 root implementation for HXL1.
The full-build check must occur **before any executable
could run**, and the research tooling must reject other
versions/models and fail closed.

Do **not** publish a `y2q` entry to v2 or v3,
copy in a generic KMI or CVE payload from a different
device, or expose an active Root action for HXL1
merely because the read-only diagnostic returns
`FIRMWARE_IDENTITY_MATCH`.

Research document location is intentionally outside the
production `artifacts/` and `src/targets/` namespaces.

## 9. Retention, rollback, and readiness (PORTING.md `9)

Keep the immutable `boot.img`, `kernel.bin`,
`config.gz`, exact SHA-256s, source-audit reports,
full build/source provenance, safe shell diagnostics,
and candidate JSON while the port remains incomplete.
Do not discard forensic inputs or overwrite historical
build logs. A verified-boot / recovery plan is required
before higher-risk hardware tests.

### Recommended development order

1. **Now:** run `tools/y2q_research_toolchain.py scan`,
   inspect `candidate.json` and manually evaluate
   possible Samsung-specific fixes/backports in 4.19;
   retain uncertainty if code diverges.
2. Verify the exact **stock extracted kernel** format,
   recover any available symbols, and establish a
   source/binary link. Establish if BTF is present;
   do not assume it.
3. Independently document the HXL1 bootloader/load chain,
   while preserving the locked verification state.
4. Review runtime permission limitations and
   Linux 4.19-specific implementation constraints,
   with no production exploit or module installed.
5. Only after independent, repeatable, authorized
   hardware evidence should module/runtime implementation
   and app integration become eligible for review.
6. Publish **nothing** until full firmware-specific
   compatibility, recovery, and access checks pass.

### Explicit acceptance gates

| Gate | Required evidence | Present status |
|---|---|---|
| Exact device/firmware identification | Full fingerprint, build, release, non-root probe | **PASS** |
| Genuine original firmware input | Recorded hashes for extracted AP data | **PASS for extracted file hashes**; booted-binary equivalence not asserted |
| Reconstructed stock source/config | Samsung archive provenance; 40 hashes; config comparisons | **PASS as audited reconstructed source**; binary identity open |
| CVE-2026-43499 code applicability | Reviewed Samsung code + fix history + exact-binary correlation | **OPEN** |
| Symbol and struct provenance | Actual extracted Image + verified ELF/BTF/layout data | **OPEN** |
| Bootloader/layout provenance | Exact HXL1 boot chain evidence | **OPEN** |
| Runtime exploit reliability/safety | Authorized, reproducible, independent hardware validation | **OPEN** |
| KernelSU 4.19 loading/behavior | Exact KMI, mandatory security constraints, clean verified run | **OPEN** |
| Safe production support matching | Reject non-HXL1/mismatched fingerprint and release | **OPEN** |
| Reboot/recovery readiness | Independently tested recovery and rollback plan | **OPEN** |

**Conclusion:** Porting `PORTING.md` to HXL1 starts with **stock
kernel evidence and device-specific feasibility**, not with making
Clang18 compile Samsung's full Linux `Image`. The user-space
diagnostic and static source review can proceed now; a working
root payload and KernelSU installation cannot be asserted.
