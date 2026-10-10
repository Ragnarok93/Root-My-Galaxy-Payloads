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

## October 10: recovered ELF map and proxy-lock symbols

Owner confirmed SHA-256 of the **reconstructed, analysis-only ELF**:
`e15f67e8253396d9e6463e5dfd78d67e324a7149842a7fbccb973ec0fd36ecdb`.
This is separate from the original `kernel.bin` checksum.

`readelf` shows ELF64 EXEC/AArch64 with three synthetic
`PT_LOAD` ranges. The first maps ELF file offset `0x240` to
the extractor-guessed `_text = 0xffffff8008080000`,
`p_filesz=0x2695260`, and flags `RWE`/alignment zero.
These are reconstruction properties; they do **not** reveal actual
runtime page permissions, the Qualcomm physical load base,
the boot entry, or the KASLR slide. The extractor's
entry point is `0xffffff800a600870` (`start_kernel`), which
must not be mistaken for the initial ARM64 boot instruction.

The recovered symbol listing contains:

| Symbol | Guessed virtual address | Candidate offset from `_text` |
|---|---|---|
| `__rt_mutex_start_proxy_lock` | `0xffffff8008147744` | `0xC7744` |
| `rt_mutex_start_proxy_lock` | `0xffffff8008147d14` | `0xC7D14` |
| `remove_waiter` | `0xffffff8008147db4` | `0xC7DB4` |
| `start_kernel` | `0xffffff800a600870` | `0x2580870` |

These offsets remain **provisional** until the recovered ELF
function bytes agree with the original verified raw ARM64 Image.
For symbols in the first LOAD segment, the hypothesis is
`raw_file_offset = symbol_va - _text` and
`elf_file_offset = 0x240 + raw_file_offset`.

### Check three small instruction windows without modifying files

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 - <<'PY'
from pathlib import Path

raw = (Path.home() / "s20-artifacts/kernel.bin").read_bytes()
elf = (Path.home() / "s20-artifacts/hxl1-research/vmlinux-stock.elf").read_bytes()
base = 0xffffff8008080000
elf_load_offset = 0x240
symbols = {
    "__rt_mutex_start_proxy_lock": 0xffffff8008147744,
    "rt_mutex_start_proxy_lock":   0xffffff8008147d14,
    "remove_waiter":               0xffffff8008147db4,
}
for name, address in symbols.items():
    raw_offset = address - base
    elf_offset = elf_load_offset + raw_offset
    raw_bytes = raw[raw_offset:raw_offset + 64]
    elf_bytes = elf[elf_offset:elf_offset + 64]
    if len(raw_bytes) != 64 or len(elf_bytes) != 64:
        raise SystemExit(f"STOP: short data at {name}")
    print(f"{name}: raw=0x{raw_offset:x}, elf=0x{elf_offset:x}")
    print(f"  first 64 instruction bytes match: {raw_bytes == elf_bytes}")
PY

ELF="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.elf"
llvm-objdump -d --disassemble-symbols=remove_waiter "$ELF" | head -n 95
llvm-objdump -d --disassemble-symbols=rt_mutex_start_proxy_lock "$ELF" | head -n 95
```

A match validates *these selected instruction windows and their
relative mapping* against the original extracted raw Image.
It does not prove that all 142,890 relocation entries were
correctly applied, that symbol boundaries are all reliable, or
that the phone's running binary/slide is the same. If any window
differs, stop and examine the extraction mapping; do not
automatically change the guessed base to force a match.

---

## October 10: original kernel ARM64 instruction-level confirmation

The owner compared the first **64 bytes** at each recovered function
offset in the original, SHA-256-verified `kernel.bin` against the
reconstructed ELF's first LOAD segment. All three were identical:

| Function | Original `kernel.bin` file offset | Byte comparison |
|---|---:|---|
| `__rt_mutex_start_proxy_lock` | `0xC7744` | **64/64 equal** |
| `rt_mutex_start_proxy_lock` | `0xC7D14` | **64/64 equal** |
| `remove_waiter` | `0xC7DB4` | **64/64 equal** |

The provided original-firmware-correlated disassembly explicitly
implements the erroneous `current` behavior found in the audited
Samsung source:

```asm
ffffff8008147de8: mrs x20, SP_EL0
ffffff8008147dec: add x21, x20, #0x8c8
ffffff8008147df8: bl  _raw_spin_lock
...
ffffff8008147e1c: str xzr, [x20, #0x8f8]
```

This kernel configuration uses `SP_EL0` to obtain `current`
while running in kernel mode. The task `pi_lock` is reached
using offset `0x8c8`, and the `pi_blocked_on` state is
cleared relative to that same task at offset `0x8f8`.
This correlates to `rtmutex.c:1077–1080`.

The proxy-start wrapper contains the actual direct cleanup
call (not merely a recovered name):

```asm
ffffff8008147d50: mov x0, x19
ffffff8008147d54: mov x1, x20
ffffff8008147d58: bl  remove_waiter
```

This is **source-and-original-firmware evidence** for the
incorrect task handling described by
[CVE-2026-43499](https://lists.openwall.net/linux-cve-announce/2026/05/21/7).
The disassembly also shows `try_to_take_rt_mutex` and a
nonzero-result cleanup path; reviewing the exact returns
is a separate correctness question. The later
[CVE-2026-53163 advisory](https://lists.openwall.net/linux-cve-announce/2026/06/25/20)
documents why an upstream cleanup change needed additional guards.
Do not assume the later introduced regression applies independently
to this older vendor build merely because the control-flow looks similar.

**Evidence scope:** an ELF reconstituted from the original
kernel will naturally share original instruction bytes;
these checks establish the relative offset mapping of these
selected windows, not independent symbol-address attestation.
They do **not** confirm byte-for-byte equality with the
kernel currently running in handset RAM, establish runtime
KASLR or demonstrate successful triggering, exploitation,
root access, or KernelSU compatibility.

**Precision about the comparison window:** the original 64-byte
byte-for-byte check at `remove_waiter` includes `mrs x20, SP_EL0`
(`+0x34`) and the `pi_lock` address calculation (at `+0x38`),
but **does not** yet include the `pi_blocked_on` clear
at `+0x68`. Likewise, the `bl remove_waiter` instruction
is `+0x44` from `rt_mutex_start_proxy_lock`, just outside
that function's first 64-byte check. These instructions
are visible in the recovered ELF disassembly, but independently
check their four-byte words against the original raw Image:

```bash
python3 - <<'PY'
from pathlib import Path

raw = (Path.home() / "s20-artifacts/kernel.bin").read_bytes()
elf = (Path.home() / "s20-artifacts/hxl1-research/vmlinux-stock.elf").read_bytes()
base = 0xffffff8008080000
load_offset = 0x240
sites = {
    "current via SP_EL0":       0xffffff8008147de8,
    "current pi_lock offset":   0xffffff8008147dec,
    "current pi_blocked_on = 0":0xffffff8008147e1c,
    "proxy calls remove_waiter":0xffffff8008147d58,
}
for label, va in sites.items():
    off = va - base
    a = raw[off:off + 4]
    b = elf[off + load_offset:off + load_offset + 4]
    if len(a) != 4 or len(b) != 4:
        raise SystemExit(f"STOP: short instruction at {label}")
    print(f"{label}: raw={a.hex()} elf={b.hex()} match={a == b}")
PY
```

A mismatch means the instruction from the reconstructed ELF
must not be treated as validated raw image bytes. Even four
matches do not establish live-device code identity or runtime
exploitability.

### Next read-only semantic-review excerpts

Inspect the complete proxy-start state transition, including
how the `task` argument is associated with `waiter` and
how failure is propagated to `futex_requeue()`:

```bash
nl -ba ~/src/samsung-y2q-hxl1-stock/kernel/locking/rtmutex.c |
  sed -n '1730,1811p'

nl -ba ~/src/samsung-y2q-hxl1-stock/kernel/futex.c |
  sed -n '2120,2205p'
```

Do not execute crash-based GhostLock proof-of-concepts on
the physical handset at this stage. Retain the original
`kernel.bin` and symbolized `vmlinux-stock.elf` unchanged.
Production `support/targets-v3.json` registration remains
blocked.

---

## October 10 — direct original-firmware instruction check: 4/4

The owner executed a read-only comparison between four recovered
ARM64 instructions and their corresponding raw bytes in the
SHA-256-verified HXL1 `kernel.bin`. All **four** match exactly:

| Critical instruction | VA in reconstructed ELF | Raw and ELF bytes (little-endian) | Result |
|---|---|---|---|
| `mrs x20, SP_EL0` (`current`) | `0xffffff8008147de8` | `144138d5` | PASS |
| `add x21, x20, #0x8c8` (`pi_lock`) | `0xffffff8008147dec` | `95222391` | PASS |
| `str xzr, [x20, #0x8f8]` (clear `pi_blocked_on`) | `0xffffff8008147e1c` | `9f7e04f9` | PASS |
| `bl remove_waiter` from proxy wrapper | `0xffffff8008147d58` | `17000094` | PASS |

This closes the earlier limited 64-byte-window qualification:
the two critical instructions just beyond the tested entry windows
are now **also** byte-confirmed. Together with the HXL1 source, this
is strong evidence for the CVE-2026-43499 task identity bug in
the **original extracted firmware**. It does not show that a
trigger is reliable or safe, nor provide live KASLR, running-RAM
verification or KernelSU privileges.

### Separate positive-return cleanup behavior

The exact owner-provided `rtmutex.c` excerpt shows:

1. `__rt_mutex_start_proxy_lock` at lines `1756–1757` returns **1**
   when `try_to_take_rt_mutex(lock, task, NULL)` acquires the
   lock immediately.
2. The wrapper at lines `1803–1806` checks `if (unlikely(ret))`,
   then invokes `remove_waiter(lock, waiter)` for **all nonzero**
   results, including `1` (successful acquisition).
3. The caller `futex.c:2159–2170` treats `ret == 1`
   as successful acquisition and wakes the waiter.
4. Recovered ELF disassembly branches from a nonzero
   `try_to_take_rt_mutex` result to a call of `remove_waiter`,
   and the exact branch instruction word matches the raw Image.

This is a legitimate **source-level control-flow concern**,
but whether that particular path causes a fault on HXL1 is
**not yet demonstrated**. The upstream
[CVE-2026-53163 advisory](https://lists.openwall.net/linux-cve-announce/2026/06/25/20)
warns about cleanup after successful acquisition, but its
reported introduced/fixed version ranges are on *newer*
kernel branches and backports; do not label this legacy 4.19
source as affected by that separate CVE just by analogy.
The CVE-2026-43499 source bug remains a separate confirmed
finding.

### Next offline gate: original waiter ownership and ABI review

Review `task_blocks_on_rt_mutex`, `rt_mutex_dequeue`, and
the futex `requeue_pi` paths in the exact audited source
to establish when `waiter->task` is populated and which
error/success branches arm a waiter. Any task layout
offsets inferred from ARM64 instructions (`0x8c8` and
`0x8f8`) remain only **field-use hypotheses** until
verified against this exact Samsung source/config.

**Status:** original firmware code correlation **PASS** for
tested instructions; **device-side exploitability, root,
kernel write capability and KernelSU loading remain OPEN**.
No experimental target goes to the production support feed.

---

## October 10: futex waiter-lifecycle evidence from owner source search

The owner's read-only `rg` in the original Samsung HXL1
`kernel/futex.c` confirms:

| Lines | Source observation |
|---|---|
| `1817–1832` | `requeue_pi_wake_futex` exists and documents waking an acquired proxy task |
| `1906–1907` | `top_waiter->task` supplies both the PID and task passed to `futex_lock_pi_atomic` |
| `2156–2158` | `rt_mutex_start_proxy_lock` receives the **waiter's** `this->rt_waiter` and `this->task` |
| `2159–2170` | `ret == 1` is treated as successful acquisition and `requeue_pi_wake_futex` |
| `2171–2186` | nonzero, nonsuccess `ret` drops PI-state reference and breaks requeue processing |

These facts **corroborate the cross-task proxy-lock usage** that
[CVE-2026-43499](https://lists.openwall.net/linux-cve-announce/2026/05/21/7)
describes. They do **not** establish where `waiter->task` is
first populated, that it is enqueued on each return path, or
that an actual use-after-free can be reproduced safely.

The initial command shown by the owner covered only
`kernel/futex.c`. The earlier requested separate
`rtmutex.c` waiter-initialization search was **not** included,
so the task/queue lifecycle check remains open.

### Next bounded read-only source inspection

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

rg -n -C 15 \
  'task_blocks_on_rt_mutex\(|waiter->task[[:space:]]*=|rt_mutex_dequeue\(' \
  ~/src/samsung-y2q-hxl1-stock/kernel/locking/rtmutex.c

nl -ba ~/src/samsung-y2q-hxl1-stock/kernel/futex.c |
  sed -n '1820,1848p;1890,1915p;2148,2188p'
```

Focus on **which task initializes the waiter, whether the
waiter is actually enqueued, and which rollback paths may
operate on an unqueued waiter**. No kernel crash tests or
privilege-escalation payloads are part of this step.

---

## October 10: waiter initialization/enqueue lifecycle now established

The owner supplied the missing bounded `rtmutex.c` and `futex.c`
source excerpts from the exact original audited HXL1 source
(previously recorded source checksums still apply).

| Observed source | What it establishes |
|---|---|
| `rtmutex.c:1149–1155` | `rt_mutex_init_waiter` initializes RB entries and sets `waiter->task = NULL` |
| `rtmutex.c:950–951` | `task_blocks_on_rt_mutex` checks `owner == task` and returns `-EDEADLK` **before** associating or enqueueing the waiter |
| `rtmutex.c:953–957` | Under `task->pi_lock`, sets `waiter->task = task`, `waiter->lock = lock`, priority and deadline |
| `rtmutex.c:962–964` | Enqueues `waiter` in lock RB tree and assigns `task->pi_blocked_on = waiter` |
| `rtmutex.c:295–301` | `rt_mutex_dequeue` returns early if the waiter's tree node is empty |
| `rtmutex.c:1077–1080` | `remove_waiter` instead locks `current->pi_lock` and clears `current->pi_blocked_on` |
| `rtmutex.c:1756–1761` | Immediate proxy acquisition can return `1` without passing through waiter setup; otherwise dispatches to `task_blocks_on_rt_mutex` |
| `rtmutex.c:1804–1806` | Wrapper cleanup on any nonzero `ret` includes both a positive success and a negative error |
| `futex.c:1837–1844` | `requeue_pi_wake_futex` unqueues `futex_q`, clears `rt_waiter`, wakes `q->task` |
| `futex.c:2156–2186` | Proxy operation takes `this->rt_waiter` and `this->task`; treats `ret == 1` as success and other nonzero values as errors |

**Two separate state conditions now need to be distinguished:**

1. **Previously enqueued waiter, error returned:** if the
   post-enqueue code returns an error, the wrapper removes
   a waiter whose associated task is `waiter->task` while
   `remove_waiter` clears the *current caller's* PI state.
   This is the source-level lifetime mismatch described by
   [CVE-2026-43499](https://lists.openwall.net/linux-cve-announce/2026/05/21/7).
   The owner has not yet supplied the *entire*
   `task_blocks_on_rt_mutex` body after line `968`,
   so error outcomes and their preconditions must still
   be checked before declaring a reproducible runtime trigger.
2. **Not enqueued:** the early `owner == task` deadlock
   check returns before setting `waiter->task`, and
   immediate successful acquisition (`ret == 1`) also
   skips waiter initialization. In these cases the wrapper
   can still call `remove_waiter` because it checks
   `if (ret)`. The RB-empty guard avoids erasing an
   unqueued RB node, but `remove_waiter` still operates
   on `current->pi_lock` and `current->pi_blocked_on`.
   That is **not** evidence that HXL1 exhibits the
   independently tracked null-task dereference introduced
   by the later [CVE-2026-53163](https://lists.openwall.net/linux-cve-announce/2026/06/25/20)
   upstream backport. The later advisory explicitly
   identifies its post-fix `waiter->task` dereference
   as the new failure mechanism.

The implications are **source-level** and corroborated by the
earlier four-word match with the original extracted ARM64
`kernel.bin`. A hardware use-after-free, kernel memory
primitive, root access and KernelSU loading remain unverified.

### Recommended next **non-destructive** review

Inspect `rtmutex.c:968–1060` in the original source to
separate errors that occur **after** enqueue from errors
that occur before association. Do not turn this finding
into an on-device panic trigger or publish a production
HXL1 payload.

```bash
nl -ba ~/src/samsung-y2q-hxl1-stock/kernel/locking/rtmutex.c |
  sed -n '968,1060p'
```

Keep the read-only device identity check and exact firmware
guards. Any later KernelSU module approach on this Samsung
4.19 kernel must be justified independently of this CVE
source/code correlation.

---

## October 10: post-enqueue chain-walk error propagation traced

The owner provided the final requested excerpt from the original audited
Samsung `rtmutex.c` (`968–1009`). Together with the previously inspected
`929–967`, `1068–1119`, and `1797–1809`, it establishes the
**complete call-chain connection from setting the waiter task to
a cleanup that uses the wrong task**:

| Step | Stock source | Observation |
|---|---|---|
| Waiter initialized and enqueued | `953–964` | `waiter->task = task`, `rt_mutex_enqueue()`, `task->pi_blocked_on = waiter` |
| No owner | `968–969` | Returns 0 without chain adjustment |
| Owner PI review | `971–986` | Checks owner PI state; may request a chain walk |
| No chain walk or no next lock | `992–993` | Returns 0, avoiding error cleanup |
| Chain adjustment | `1000–1009` | Releases/reacquires `wait_lock` around `rt_mutex_adjust_prio_chain(owner,chwalk,lock,next_lock,waiter,task)`; returns its result unchanged |
| Proxy wrapper | `1797–1809` | Any nonzero return invokes `remove_waiter(lock,waiter)` |
| Incorrect state cleanup | `1077–1080` | Dequeues the waiter while holding `current->pi_lock` and clears `current->pi_blocked_on`, **not the waiter task's state** |

The official Linux advisory for
[CVE-2026-43499](https://lists.openwall.net/linux-cve-announce/2026/05/21/7)
identifies precisely this wrong-task PI state handling in
`futex_requeue` proxy-lock rollback. This provides strong
source-level evidence of the CVE defect in the original HXL1
code, with the previously recorded **four exact raw-image
instruction matches** backing the relevant binary behavior.

**Important constraints:** a chain-walk is performed only if
`chain_walk && next_lock`; the excerpt does **not** show the
callee `rt_mutex_adjust_prio_chain()` returning an error on a
particular real workload. The defect is therefore verified
**in source and the tested original binary instructions**;
an on-device use-after-free, arbitrary kernel memory
access, root, or KernelSU installation are *not* verified.

### Next milestone: legacy 4.19 ABI/config readiness (read-only)

Move away from repeated code excerpts and inventory
exact original-kernel symbols and config constraints:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

NM="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm"
gzip -dc "$HOME/s20-artifacts/config.gz" |
  grep -E '^(CONFIG_(MODULES|MODVERSIONS|MODULE_SIG_FORCE|MODULE_FORCE_LOAD|TRIM_UNUSED_KSYMS|KPROBES|KALLSYMS|KALLSYMS_ALL|UH_RKP|KDP_CRED|KDP_NS|SECURITY_DEFEX)=|# CONFIG_(MODULE_FORCE_LOAD|TRIM_UNUSED_KSYMS|KPROBES) is not set)' || true

grep -E ' (call_usermodehelper_exec_work|init_task|root_task_group|selinux_state|system_unbound_wq|rt_mutex_start_proxy_lock|remove_waiter)

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

readelf -hW "$HOME/s20-artifacts/hxl1-research/vmlinux-stock.elf" |
  grep -E 'Class:|Machine:|Entry point'
```

Treat extracted addresses as **provisional** until source/ELF
cross-checks pass. This inventory is not a kernel loader,
exploit or writable-memory mapping; KernelSU 4.19 support
and production-feed registration remain blocked.

---

## October 10: HXL1 4.19 KernelSU module/ABI feasibility inventory

The owner ran the original extracted `config.gz` and
`llvm-nm -n` from the original kernel-derived
`vmlinux-stock.elf`. This is an **offline inventory**, not
a working KernelSU module. Exact running release:
`4.19.113-27095354`.

| Observed option | Result | Consequence |
|---|---|---|
| `CONFIG_MODULES` | `y` | The kernel has a module subsystem |
| `CONFIG_MODULE_SIG_FORCE` | `y` | Normal Linux module loading requires a cryptographically accepted signature |
| `CONFIG_MODVERSIONS` | `y` | Symbol-version CRC compatibility matters for normal module linking/loading |
| `CONFIG_MODULE_FORCE_LOAD` | unset | Cannot rely on normal force-loading |
| `CONFIG_TRIM_UNUSED_KSYMS` | unset | No automatic unused export trimming; still not proof of an export |
| `CONFIG_KPROBES` | unset | Existing kernel does not offer kprobe-based hooks |
| `CONFIG_KALLSYMS`, `CONFIG_KALLSYMS_ALL` | `y` | Internal symbols were recoverable offline; not necessarily exported or accessible to the shell |
| `CONFIG_UH_RKP`, `CONFIG_KDP_CRED`, `CONFIG_KDP_NS`, `CONFIG_SECURITY_DEFEX` | `y` | Samsung-specific credential, text and policy constraints |

Normal signed-module requirements are documented by
[Linux module-signing](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html).
The existing repository's `kernelsu/README.md` focuses on
Samsung KernelSU v3.2.5 with firmware-specific assets for
**other kernel families**, not HXL1 4.19. Its manual
relocation technique does not inherently remove the
kernel's signature check or privilege requirements.
The [upstream KernelSU non-GKI integration guide](https://kernelsu.org/guide/how-to-integrate-for-non-gki.html)
covers much older v0.9.5 and generally assumes that
a modified kernel can be built and booted; this locked
S20+ cannot assume that path.

### Firmware-derived symbols — **names, not accepted module imports**

| Name | `llvm-nm` output from recovered ELF |
|---|---|
| `call_usermodehelper_exec_work` | `ffffff80080d84f4 t` |
| `rt_mutex_start_proxy_lock` | `ffffff8008147d14 T` |
| `remove_waiter` | `ffffff8008147db4 t` |
| `system_unbound_wq` | `ffffff800ac1e708 T` |
| `init_task` | `ffffff800ac2f9c0 T` |
| `root_task_group` | `ffffff800b211c00 T` |
| `selinux_state` | **`U selinux_state` (undefined; no verified address)** |

The extractor reconstructed broad RWE `PT_LOAD` regions and
a synthetic symbol table. For example, `init_task`
and `root_task_group` represent data objects even though
`llvm-nm` prints `T`; symbol-type letters in this
recovered ELF must not be interpreted as ground truth
about ELF sections or exportability. A symbol name's
presence does **not** mean `EXPORT_SYMBOL` exists, and
`U selinux_state` must **not** become an address offset.

### Next no-device-write checks on WSL2

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

CFG="$HOME/s20-artifacts/config.gz"
NM="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm"

gzip -dc "$CFG" |
  grep -E '^(CONFIG_(SMP|PREEMPT|PREEMPT_VOLUNTARY|MODULE_UNLOAD|MODULE_SIG|MODULE_SIG_ALL|MODULE_SIG_FORCE|MODULE_SIG_SHA512|MODVERSIONS|SECURITY_SELINUX|SECURITY_SELINUX_DISABLE|SECURITY_SELINUX_DEVELOP|LTO_CLANG)=|# CONFIG_(SMP|PREEMPT|MODULE_UNLOAD|MODULE_SIG_ALL|SECURITY_SELINUX_DISABLE|SECURITY_SELINUX_DEVELOP|LTO_CLANG) is not set)' || true

grep -Ei ' (selinux_state|selinux_enforcing|selinux_initialized|security_load_policy|kdp_usecount_inc_not_zero|kdp_usecount_dec_and_test|kdp_assign_pgd|defex_.*)

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
 "$NM" |
  head -n 70 || true

find "$HOME/src/samsung-y2q-hxl1-stock" -name Module.symvers -type f -print
```

`Module.symvers` from another phone, the Clang18
compatibility output, or a different built configuration
does not establish the original HXL1 symbol CRC table.
A reconstructed `vmlinux-stock.elf` can be used for
**offline symbol existence and disassembly checks**,
but not as proof that an import is in the actual
kernel export table.

**Gate status:** exact original kernel symbol inventory
exists; *module ABI, `vermagic`, full export/CRC map,
legacy 4.19 KernelSU hooks, loader privileges and
Samsung security compatibility all remain open*.
No `kernelsu.ko` or `ksud` for HXL1 has been verified.
Do not publish `support/targets-v3.json`.

---

## October 10: original HXL1 SELinux and module metadata follow-up

The owner checked exact `G986U1UESCHXL1` `config.gz` and
`vmlinux-stock.nm` after the initial Linux 4.19 module
compatibility inventory:

| Key | Owner-reported result |
|---|---|
| `CONFIG_PREEMPT` | `y` |
| `CONFIG_SMP` | `y` |
| `CONFIG_MODULE_UNLOAD` | `y` |
| `CONFIG_MODULE_SIG` | `y` |
| `CONFIG_MODULE_SIG_ALL` | `y` |
| `CONFIG_MODULE_SIG_SHA512` | `y` |
| `CONFIG_SECURITY_SELINUX` | `y` |
| `CONFIG_SECURITY_SELINUX_DEVELOP` | `y` |
| `selinux_enforcing` | recovered ELF listing: `ffffff800a4dd200 T selinux_enforcing` |
| `selinux_state` | recovered ELF listing: `U selinux_state` (undefined; **not a usable address**) |
| `kdp_usecount_inc_not_zero`, `kdp_usecount_dec_and_test`, `kdp_assign_pgd` | no matches for these **exact names** in this recovered-ELF grep |
| Original `Module.symvers` | **none found** in reconstructed Samsung source tree |

Prior output also established `CONFIG_MODVERSIONS=y`,
`CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_KPROBES=n`,
`CONFIG_UH_RKP=y`, `CONFIG_KDP_CRED=y`,
`CONFIG_KDP_NS=y`, and `CONFIG_SECURITY_DEFEX=y`.

**Module signatures:** `CONFIG_MODULE_SIG_ALL=y`
automates signing during `modules_install`; it does **not**
create a trusted key available to users. `MODULE_SIG_FORCE=y`
requires the installed kernel to trust the signer's key
before normal module insertion.
[Kernel documentation](https://docs.kernel.org/admin-guide/module-signing.html)
explains the separation. Similarly,
`CONFIG_SECURITY_SELINUX_DEVELOP=y` does not mean the
running SELinux policy is permissive or can be freely disabled.

**Interpreting the names:** `selinux_enforcing` is a
provisional reconstructed ELF address; its `T` type may
not represent a text symbol because `vmlinux-to-elf` builds
synthetic load sections. The `selinux_state` undefined
entry must never be used as a usable symbol address.
The missing **exact names** of KDP helpers does not show
Samsung's protections are absent or that an equivalent
ABI cannot be present under another name or inline code.

**Symbol CRCs:** the original Samsung source directory
has no `Module.symvers`. Under `CONFIG_MODVERSIONS=y`
that file is normally **created by a complete kernel
build** and records exports/CRCs; it is not ordinarily
guaranteed to be included with vendor source.
[Linux kbuild documentation](https://docs.kernel.org/kbuild/modules.html)
also describes kernel export and CRC tables. Investigating
`__ksymtab`, `__kcrctab` and `__crc_` recovered symbols
may be useful, but **must not** be presented as an already
recovered `Module.symvers`.

### Next read-only stock-export and SELinux source check

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

NM="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm"
SRC="$HOME/src/samsung-y2q-hxl1-stock"

grep -E ' (__ksymtab_|__kcrctab_|__crc_|__kstrtab_)(init_task|system_unbound_wq|selinux_enforcing|call_usermodehelper_exec_work|commit_creds|prepare_kernel_cred|module_layout)

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

grep -E ' (__start___ksymtab|__stop___ksymtab|__start___kcrctab|__stop___kcrctab|__start___ksymtab_gpl|__stop___ksymtab_gpl)

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

rg -n -m 3 'selinux_enforcing|selinux_state' "$SRC/security/selinux" |
  head -n 65 || true

rg -n -m 3 'kdp_usecount_inc_not_zero|kdp_usecount_dec_and_test|kdp_assign_pgd' \
  "$SRC/include" "$SRC/security" "$SRC/kernel" |
  head -n 65 || true
```

Use this output to separate symbol **presence**, original
source definitions, standard **EXPORT_SYMBOL** status, and
CRC verification. They are not interchangeable.
Do **not** borrow `Module.symvers`, `vermagic` or
SELinux offsets from the project's 5.x and 6.x Samsung
targets. Do **not** install a module or publish HXL1
support from this metadata alone.

---

## October 10: **actual** original-HXL1 module export/CRC tables found

The owner supplied exact output from the reconstructed stock
`vmlinux-stock.nm` and the Samsung HXL1 source.

| Firmware-recovered boundary | Address | Derived length | 4.19 PREL32 entries |
|---|---|---:|---:|
| `__start___ksymtab` | `0xffffff800a4e70e0` | — | — |
| `__stop___ksymtab` = `__start___ksymtab_gpl` | `0xffffff800a4f58f8` | `0xe818` | **7,427** ordinary × 8 bytes |
| `__stop___ksymtab_gpl` = `__start___kcrctab` | `0xffffff800a4ffe10` | `0xa518` | **5,283** GPL × 8 bytes |
| `__stop___kcrctab` | `0xffffff800a50721c` | `0x740c` | **7,427** ordinary CRC × 4 bytes |

The first source/output check demonstrates a **one-to-one
7427:7427 ordinary export/CRC slot correspondence**.
Linux 4.19's `include/linux/export.h` defines the
`CONFIG_HAVE_ARCH_PREL32_RELOCATIONS` compact
8-byte `struct kernel_symbol` representation; the
Samsung exact-config value has **not** yet been read,
so this is a strong layout hypothesis, not a complete
table integrity validation. For relative CRC
representations `CONFIG_MODULE_REL_CRCS` must be
checked before interpreting raw 32-bit entries. See
[4.19 export.h](https://cos.googlesource.com/third_party/kernel/+/refs/tags/upstream/v4.19.149/include/linux/export.h)
and [4.19 kernel/module.c](https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux-stable.git/+/refs/tags/v4.19.268/kernel/module.c).

Recovered export entries and ranges:

| Name | Recovered `__ksymtab_*` VA | Namespace | Entry index |
|---|---|---|---:|
| `commit_creds` | `0xffffff800a4e96a0` | ordinary | 1208 |
| `init_task` | `0xffffff800a4ed340` | ordinary | 3148 |
| `module_layout` | `0xffffff800a4ef528` | ordinary | 4233 |
| `prepare_kernel_cred` | `0xffffff800a4f0ff0` | ordinary | 5090 |
| `system_unbound_wq` | `0xffffff800a4fdfd8` | **GPL** | 4316 |

The **GPL table** has a separate CRC range,
`__start___kcrctab_gpl`, which the original
search did not request. A name found in `kallsyms`
but lacking a `__ksymtab_*` entry is not ordinary
module-exportable. These names/entry indices are
**offline observations**, not proof of usable KernelSU
hooks, module permissions or a signature accepted by
the device.

### SELinux protected data: source found, ELF address still missing

The *original HXL1 Samsung source*, not just upstream,
declares:

- `security/selinux/include/security.h:104,122`:
  `struct selinux_state` and its external declaration.
- `security/selinux/hooks.c:108`:
  `struct selinux_state selinux_state __rticdata;`
- `security/selinux/hooks.c:209`:
  `int selinux_enforcing __kdp_ro;`

Thus the reconstructed ELF's `U selinux_state` is
**not evidence that the object is absent in the source**.
The protected `__rticdata` and `__kdp_ro` placements
require specific vendor source/linker review; a
reconstructed ELF may not represent all data sections
or relocation targets accurately. The apparent `T`
type for `selinux_enforcing` is also synthetic.
Do **not** treat these as writable globals or infer
the live address of `selinux_state`.
Samsung RKP/KDP protected-data section context:
[Impalabs RKP compendium](https://blog.impalabs.com/2101_samsung-rkp-compendium.html).

### Next reproducible offline check (no full kernel rebuild)

A new **read-only** script, `tools/y2q_export_table_audit.py`,
compares the raw firmware SHA-256 with the HXL1
manifest, checks its ARM64 header, validates the
recovered export boundaries and maps selected
8-byte PREL32 entries **back into original raw
`kernel.bin` bytes**. It refuses non-HXL1 input,
unconfirmed PREL32 configuration, unexpected entry
layout, invalid bounds and bad decoded symbol names.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

gzip -dc ~/s20-artifacts/config.gz |
  grep -E '^(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS|CONFIG_MODULE_REL_CRCS|CONFIG_MODVERSIONS)=' || true

grep -E ' (__start___kcrctab_gpl|__stop___kcrctab_gpl|__start___ksymtab_gpl_future|__stop___ksymtab_gpl_future)

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
 \
  ~/s20-artifacts/hxl1-research/vmlinux-stock.nm || true

python3 tools/y2q_export_table_audit.py \
  --kernel-bin ~/s20-artifacts/kernel.bin \
  --nm ~/s20-artifacts/hxl1-research/vmlinux-stock.nm \
  --config-gz ~/s20-artifacts/config.gz
```

The audit prints structured JSON to stdout; it
does not write files, request root, read device memory,
build a module, patch SELinux or alter kernel code.
Its `candidateCrc` values are **only provisional**
until decoded according to the exact HXL1
`kernel/module.c` semantics and checked independently
against a known versioned import. Matching counts
alone do not reconstruct full `Module.symvers`.
The HXL1 production/root/KernelSU gates remain open.

---

## October 10: first direct PREL32 symbol+CRC audit **passed**

The owner ran `tools/y2q_export_table_audit.py` from the
`d262356` branch against the original,
SHA-256-verified HXL1 raw Image and recovered
`vmlinux-stock.nm`. The read-only audit succeeded:
five of five selected `__ksymtab_*` records yielded
the **expected symbol name and correct target address**
when decoded from original raw ARM64 Image bytes
using `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y`.

| Original exported name | Class | Raw slot bytes (LE) | Conditional absolute CRC candidate |
|---|---|---|---|
| `commit_creds` | ordinary | `794fccf2` | `0xf2cc4f79` |
| `prepare_kernel_cred` | ordinary | `5caf6fb8` | `0xb86faf5c` |
| `init_task` | ordinary | `e2bd0572` | `0x7205bde2` |
| `module_layout` | ordinary | `758162b6` | `0xb6628175` |
| `system_unbound_wq` | GPL | `3246c1d4` | `0xd4c14632` |

The owner also reported `__start___kcrctab_gpl =
0xffffff800a50721c` and `__stop___kcrctab_gpl =
0xffffff800a50c4a8`, a `0x528c`-byte range. This is
**5,283 four-byte slots**, exactly matching the
**5,283 GPL exported symbol entries**.
The ordinary table also matches at **7,427:7,427**.

**CRC interpretation remains provisional:** the
extracted configuration explicitly contains
`CONFIG_MODVERSIONS=y`, but the audit reports
`CONFIG_MODULE_REL_CRCS = absent`; this does
**not** equal an explicit `# CONFIG_MODULE_REL_CRCS
is not set` line. In Linux 4.19, the relevant
`kernel/module.c` `check_version` uses
`IS_ENABLED(CONFIG_MODULE_REL_CRCS)` to choose
`resolve_rel_crc(crc)` or a direct `*crc`
read. The `include/linux/export.h` macro also
uses the presence of `CONFIG_MODULE_REL_CRCS`
to select relative or direct CRC encodings.
The direct little-endian values above are
**candidate module-version CRCs if the symbol
is truly undefined in the shipped build**.
See [upstream Linux 4.19 module.c](https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux-stable.git/+/refs/tags/v4.19.268/kernel/module.c)
and [Linux 4.19 export.h](https://cos.googlesource.com/third_party/kernel/+/refs/tags/upstream/v4.19.149/include/linux/export.h).
Neither matching export names nor raw bytes proves
the matching `Module.symvers` CRC values without
checking this Samsung source and at least one
independent CRC reference.

The read-only auditor was revised to check **both**
GPL and ordinary CRC-table spans and report an
explicitly labeled
`candidateCrcAssumingAbsolute` value when
`MODULE_REL_CRCS` is absent rather than
silently treating that absence as a proven `n`.
**No module-load acceptance can be inferred.**

### Next bounded verification

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

SRC="$HOME/src/samsung-y2q-hxl1-stock"
rg -n 'MODULE_REL_CRCS|resolve_rel_crc|crcval = \*crc|__CRC_SYMBOL' \
  "$SRC/init/Kconfig" "$SRC/kernel/module.c" "$SRC/include/linux/export.h" \
  "$SRC/arch/arm64/Kconfig" || true

gzip -dc ~/s20-artifacts/config.gz |
  grep -E 'MODULE_REL_CRCS|MODVERSIONS|HAVE_ARCH_PREL32' || true

python3 tools/y2q_export_table_audit.py \
  --kernel-bin ~/s20-artifacts/kernel.bin \
  --nm ~/s20-artifacts/hxl1-research/vmlinux-stock.nm \
  --config-gz ~/s20-artifacts/config.gz
```

These steps run only on WSL2. Do not use CRC
candidate numbers as an authorization to force-load
unsigned code; the actual device has
`CONFIG_MODULE_SIG_FORCE=y` and kernel data protections.
No firmware-specific KernelSU 4.19 module has been
built or loaded; HXL1 is not in the production
support feed.

---

## October 9 — original HXL1 CRC slot audit completed

The owner ran the new read-only `y2q_export_table_audit.py`
against the verified `kernel.bin`
(SHA-256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`)
and the recovered `vmlinux-stock.nm`.

**Source from audit output:**

- `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y`
- `CONFIG_MODVERSIONS=y`
- `CONFIG_MODULE_REL_CRCS` **absent** (not shown as explicitly `n`)
- `CONFIG_MODULE_SIG_FORCE=y`
- ordinary `__ksymtab`: **7,427** entries; ordinary `__kcrctab`: **7,427** entries
- GPL `__ksymtab_gpl`: **5,283** entries; `__kcrctab_gpl` spans
  `0xffffff800a50721c` through `0xffffff800a50c4a8`:
  **5,283** four-byte slots

For the following five exports, direct PREL32 target
decoding agrees with recovered `kallsyms` **and** raw
symbol names agree exactly:

| Kernel export | Namespace | Raw CRC bytes | Little-endian candidate |
|---|---|---|---|
| `commit_creds` | ordinary | `794fccf2` | `0xf2cc4f79` |
| `prepare_kernel_cred` | ordinary | `5caf6fb8` | `0xb86faf5c` |
| `init_task` | ordinary | `e2bd0572` | `0x7205bde2` |
| `module_layout` | ordinary | `758162b6` | `0xb6628175` |
| `system_unbound_wq` | GPL-only | `3246c1d4` | `0xd4c14632` |

**Interpretation:** in Linux 4.19, `CONFIG_MODULE_REL_CRCS`
selects relative-offset decoding. If the macro is
undefined, the default branch uses direct 32-bit CRC
words (see `include/linux/export.h` and `kernel/module.c`).
The absent option in HXL1's exact extracted configuration
is therefore **consistent with** direct CRC slots.
The entries above are still only **candidates** until the
Samsung-specific source and independent CRC evidence are
checked. Do not misstate this as fully recovered
`Module.symvers` or a loadable signed module.

**Code-quality follow-up:** the auditor's subsequent GPL
CRC count amendment introduced an unmatched parenthesis
in an `if` statement. That syntax defect was corrected
and a synthetic regression suite added in
`tools/test_y2q_export_table_audit.py`.
The `y2q-identity-probe.yml` CI now compiles and runs
the export audit tests when those two files change.

### Next read-only WSL2 command

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m py_compile tools/y2q_export_table_audit.py
python3 -m unittest -v tools/test_y2q_export_table_audit.py

# Confirm Samsung's exact CRC decoding branches.
rg -n -C 4 'CONFIG_MODULE_REL_CRCS|__CRC_SYMBOL|__kcrctab' \
  ~/src/samsung-y2q-hxl1-stock/include/linux/export.h \
  ~/src/samsung-y2q-hxl1-stock/kernel/module.c

python3 tools/y2q_export_table_audit.py \
  --kernel-bin ~/s20-artifacts/kernel.bin \
  --nm ~/s20-artifacts/hxl1-research/vmlinux-stock.nm \
  --config-gz ~/s20-artifacts/config.gz
```

**Scope:** no on-device kernel modifications or loading;
runtime bootloader, signature, RKP/KDP and KernelSU 4.19
compatibility gates remain unverified and closed.

---

## October 9 — exact Samsung source confirms direct CRC interpretation

The owner reran the read-only original Image export audit and
the Python regression suite (**5/5 tests passed**). The exact assembled
Samsung HXL1 source includes the CRC representation conditional in
`include/linux/export.h` at lines 27–38:

- `#if defined(CONFIG_MODULE_REL_CRCS)`: emit 32-bit
  **relative** reference (`.long __crc_##sym - .`)
- `#else`: emit 32-bit **direct** CRC (`.long __crc_##sym`)

And `kernel/module.c` at lines 1346–1349 uses the paired
loader behavior:

```c
if (IS_ENABLED(CONFIG_MODULE_REL_CRCS))
    crcval = resolve_rel_crc(crc);
else
    crcval = *crc;
```

The owner-supplied exact original `config.gz` has
`CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y` and
`CONFIG_MODVERSIONS=y`, but does **not define**
`CONFIG_MODULE_REL_CRCS`. This selects the
non-relative branch of the Samsung source. Therefore
`commit_creds=0xf2cc4f79`,
`prepare_kernel_cred=0xb86faf5c`,
`init_task=0x7205bde2`,
`module_layout=0xb6628175` and
`system_unbound_wq=0xd4c14632`
are **source-consistent direct module version CRC words**
from the verified original Image. Their export names
and target addresses were all checked against the
recovered `kallsyms` listing (5/5).

The audit now accepts optional `--source-dir`. With
that option, it inspects Samsung's own export/header
and module-loader representations and reports
`sourceConsistentDirectCrc` per matching entry.
The check is intentionally source-level; it
does **not** certify the complete reconstructed
source against the deployed kernel, synthesize a
trusted module signer, override Samsung security
checks, or produce a flashable root payload.

**Run after pulling updates:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m py_compile tools/y2q_export_table_audit.py
python3 -m unittest -v tools/test_y2q_export_table_audit.py

python3 tools/y2q_export_table_audit.py \
  --kernel-bin ~/s20-artifacts/kernel.bin \
  --nm ~/s20-artifacts/hxl1-research/vmlinux-stock.nm \
  --config-gz ~/s20-artifacts/config.gz \
  --source-dir ~/src/samsung-y2q-hxl1-stock
```

The original GPL and ordinary export count/CRC count
pairs both match: `7427/7427` and `5283/5283`.
No KernelSU/module-loader compatibility or ability
to insert signed kernel modules has been established.

---

## October 9: owner verified source-aware CRC extraction; KernelSU 4.19 compatibility gate

**Observed on owner WSL2:** `python3 -m py_compile
tools/y2q_export_table_audit.py` completed without error;
`python3 -m unittest -v tools/test_y2q_export_table_audit.py`
passed **7/7 tests in 0.021 s**; and the real
`--source-dir ~/src/samsung-y2q-hxl1-stock` audit passed.

The script independently confirmed the original extracted
`kernel.bin` SHA-256
`ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`,
the PREL32 names/targets of five exports, and matched the
selected original-Image CRC slots to Samsung's
`include/linux/export.h` and `kernel/module.c` logic.

| Check | Result |
|---|---|
| Standard exports / standard CRC slots | 7,427 / 7,427 |
| GPL exports / GPL CRC slots | 5,283 / 5,283 |
| Independently name/value-correlated sampled exports | 5/5 |
| Exact Samsung source direct-CRC branch | Confirmed for undefined `CONFIG_MODULE_REL_CRCS` |
| Standalone stock `Module.symvers` | Not found |
| Trusted signing key / accepted module | Not established |
| Live root / KernelSU module on S20+ | Not established |

Source-consistent exact Image CRC words:
`commit_creds=0xf2cc4f79`,
`prepare_kernel_cred=0xb86faf5c`,
`init_task=0x7205bde2`,
`module_layout=0xb6628175`,
`system_unbound_wq=0xd4c14632` (GPL).

This **completes the selected export/CRC semantic audit**.
An externally generated, matching `Module.symvers`
comparison is still absent, but repeating this
same five-entry check is no longer the priority.

### Harder blocker found in the existing KernelSU Samsung patch

Direct repository review of
`kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch`
shows the current late-load fallback relies on:

- `register_kretprobe(&setresuid_kretprobe)` for the
  `__arm64_sys_setresuid` compatibility hook; that
  branch is gated by `CONFIG_KRETPROBES`.
- `register_kprobe(...)` for several sucompat
  syscalls and the Samsung DEFEX enforcement hook.
- `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT` makes
  `ksu_patch_text(...)` explicitly return
  `-EOPNOTSUPP`.

**HXL1's actual `CONFIG_KPROBES=n` means these
Samsung probe fallback hooks are not presently
available**. The existing patch and prebuilt modules
are therefore **not** shown compatible with
Linux `4.19.113-27095354`. Coupled with
`CONFIG_MODULE_SIG_FORCE=y` and Samsung
`RKP/KDP/DEFEX`, successful offline export/CRC
parsing does **not** supply a working loading or
hooking method.

Recommended **read-only** next gate:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

gzip -dc ~/s20-artifacts/config.gz |
  grep -E '^(CONFIG_(KPROBES|KRETPROBES|FTRACE|FUNCTION_TRACER|DYNAMIC_FTRACE|FTRACE_SYSCALLS|BPF|BPF_SYSCALL|HAVE_KPROBES|HAVE_KRETPROBES)=|# CONFIG_(KPROBES|KRETPROBES|FTRACE|FUNCTION_TRACER|DYNAMIC_FTRACE|FTRACE_SYSCALLS|BPF|BPF_SYSCALL) is not set)' || true
```

This is a capability inventory, **not** permission
to hook a protected kernel or load a module.
Prioritize a sound legacy 4.19 implementation feasibility
assessment, including an authorized loading path,
over more CRC extraction or a full Image rebuild.
Do not register HXL1 in the Root My Galaxy
production support feed or present an exploit as working.

---

## October 10 — HXL1 BPF and ftrace hook feasibility check

The owner inspected the exact original `G986U1UESCHXL1`
`config.gz` after confirming source-consistent module CRCs.

| Original HXL1 configuration | Observed state | Correct interpretation |
|---|---|---|
| `CONFIG_BPF` | `y` | BPF core compiled |
| `CONFIG_BPF_SYSCALL` | `y` | BPF syscall compiled; **access subject to policy/privileges** |
| `CONFIG_KPROBES` | **n** | Kernel does not support kprobe-based interception |
| `CONFIG_FTRACE` | `y` | General trace infrastructure compiled |
| `CONFIG_FUNCTION_TRACER` | **n** | Normal ftrace function-entry callbacks unavailable |
| `CONFIG_FTRACE_SYSCALLS` | **n** | Dedicated ftrace syscall tracing unavailable |
| `CONFIG_KRETPROBES` | Not printed | Do not treat missing grep output as a confirmed build setting; kretprobes depend on kprobes |
| `CONFIG_DYNAMIC_FTRACE` | Not printed | Do not treat missing grep output as a confirmed setting; 4.19 dynamic ftrace depends on function tracing |

The important distinction is that **ftrace core is not
the same as the function tracer**, and **BPF syscalls
are not automatically unrestricted BPF probes**.
The Linux 4.19 [ftrace overview](https://www.kernel.org/doc/html/v4.19/trace/ftrace.html)
distinguishes its event-tracing framework from the
function tracer, and [function-hook documentation](https://www.kernel.org/doc/html/v4.19/trace/ftrace-uses.html)
discusses function callbacks separately.

The current `kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch`
uses `register_kprobe` for Samsung sucompat and
DEFEX intercepts, and `register_kretprobe` for its
setresuid fallback. The exact HXL1 `CONFIG_KPROBES=n`
rules out **those existing hook paths**.
The patch's `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT`
also makes direct text patching return
`-EOPNOTSUPP`. So **there is no verified current
4.19-compatible KernelSU hook backend**.

This does not imply that every kernel-observation method
is absent. Static tracepoints or perf facilities may exist,
but they are **not substitutes for arbitrary credentials,
syscall modification or privileged module loading**.
Kernel signature enforcement
(`CONFIG_MODULE_SIG_FORCE=y`), a **locked bootloader**
and Samsung RKP/KDP/DEFEX are still separate blockers.
The earlier CVE-2026-43499 source/binary defect has
not been shown to produce a working privilege escalation
or loading primitive.

### Next bounded, read-only configuration inventory

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

gzip -dc ~/s20-artifacts/config.gz |
  grep -E '^(CONFIG_(BPF_EVENTS|BPF_JIT|BPF_JIT_ALWAYS_ON|PERF_EVENTS|TRACEPOINTS|EVENT_TRACING|KPROBE_EVENTS|KRETPROBES|UPROBES|UPROBE_EVENTS|DYNAMIC_FTRACE|FUNCTION_GRAPH_TRACER|HAVE_KPROBES|HAVE_KRETPROBES)=|# CONFIG_(BPF_EVENTS|BPF_JIT|BPF_JIT_ALWAYS_ON|PERF_EVENTS|TRACEPOINTS|EVENT_TRACING|KPROBE_EVENTS|KRETPROBES|UPROBES|UPROBE_EVENTS|DYNAMIC_FTRACE|FUNCTION_GRAPH_TRACER) is not set)' || true
```

**No root, unsigned module load, KernelSU initialization,
live code patch or exploit chain has been demonstrated.**
Keep HXL1 out of `support/targets-v3.json`.

---

## October 10: tracing/BPF stock-config inventory complete

The owner's latest read-only WSL2 check of exact HXL1
`config.gz` supplies the remaining feature states:

| Original stock kernel setting | Value | What it means |
|---|---|---|
| `CONFIG_PERF_EVENTS` | `y` | Kernel perf-event infrastructure; attachment can be permission-gated |
| `CONFIG_TRACEPOINTS` | `y` | Static tracepoints compiled into the kernel |
| `CONFIG_EVENT_TRACING` | `y` | Kernel trace-event framework |
| `CONFIG_UPROBES`, `CONFIG_UPROBE_EVENTS` | `y`, `y` | User-space instruction probing and events, not generic kernel probes |
| `CONFIG_BPF_EVENTS` | `y` | BPF event integration exists; hook types and privileges depend on exact kernel/policy |
| `CONFIG_BPF_JIT` | **n** | Native-code JIT disabled; does **not** mean the BPF interpreter is absent |
| `CONFIG_BPF`, `CONFIG_BPF_SYSCALL` | `y`, `y` (previous check) | Core and syscall compiled, no implication that the Android shell can use them |
| `CONFIG_KPROBES` | **n** (previous check) | Kprobes and dependent kretprobe paths unavailable |
| `CONFIG_FTRACE` | `y` (previous check) | Ftrace framework present |
| `CONFIG_FUNCTION_TRACER`, `CONFIG_FTRACE_SYSCALLS` | **n**, **n** (previous check) | Function tracer and syscall-specific ftrace not compiled |

Linux 4.19 kernel documentation differentiates
[event tracing](https://www.kernel.org/doc/html/v4.19/trace/events.html),
[tracepoints](https://www.kernel.org/doc/html/v4.19/trace/tracepoints.html),
and [user-space uprobe events](https://www.kernel.org/doc/html/v4.19/trace/uprobetracer.html).
None alone provides the existing KernelSU Samsung v3.2.5
patch's `register_kprobe`, `register_kretprobe`,
or arbitrary protected kernel-text modification requirements.

**Conclusion:** basic read-only source/config capability
inventory is complete. Further repeating stock
`CONFIG_*` searches is unlikely to unlock root.
The next meaningful gate is an **authorized and verifiable
module loading path plus HXL1-specific KernelSU hook
compatibility**, not another CRC or tracing scan.
This has **not** been established for the locked
`SM-G986U1`. `CONFIG_MODULE_SIG_FORCE=y`,
Samsung `RKP/KDP/DEFEX` and missing function probes
remain independent obstacles.

### Optional non-root device permission inventory

The following commands ask the phone only to **read**
identity, kernel tracing availability and permission
restrictions; they do **not** enable any event, attach
BPF, mount anything or write kernel memory.

```bash
adb shell '
id
getenforce
for p in /proc/sys/kernel/perf_event_paranoid \
         /proc/sys/kernel/unprivileged_bpf_disabled; do
    printf "%s: " "$p"
    cat "$p" 2>/dev/null || echo unavailable
done
for p in /sys/kernel/tracing \
         /sys/kernel/debug/tracing; do
    ls -ld "$p" 2>/dev/null || echo "$p: inaccessible"
done
'
```

An unavailable path may be unmounted, access denied,
or absent for this build. Do not treat it as proof of
missing kernel support or assume root privileges
from the Shizuku/ADB shell. The project's existing
no-root/locked-bootloader status stays unchanged, and
the HXL1 profile remains outside production support.

---

## October 10: physical S20+ ADB shell tracing permission results

The owner executed the planned **read-only** `adb shell`
command on the original `G986U1UESCHXL1` firmware.
The returned shell identity is:

```text
uid=2000(shell) gid=2000(shell)
groups include 3012(readtracefs)
context=u:r:shell:s0
getenforce: Enforcing
/proc/sys/kernel/perf_event_paranoid: -1
/proc/sys/kernel/unprivileged_bpf_disabled: 0
/sys/kernel/tracing: drwxr-xr-x root readtracefs
/sys/kernel/debug/tracing: drwxr-xr-x root readtracefs
```

**Interpretation and limits:**

- The ADB shell is **not root** and runs in an
  enforcing SELinux domain. Do not treat the
  `readtracefs` group as blanket permission
  to change tracing state.
- `perf_event_paranoid=-1` removes
  Linux's usual `perf_event_paranoid` restrictions,
  but other controls (notably SELinux on Android)
  can still deny particular `perf_event_open`
  calls. See
  [Linux perf security guidance](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html)
  and the
  [Android init perf permission logic](https://android.googlesource.com/platform/system/core/+/refs/tags/android-11.0.0_r3/init/security.cpp).
- `unprivileged_bpf_disabled=0` means this
  **sysctl** does not globally prohibit
  unprivileged BPF; it does **not** prove
  Android shell can load BPF programs,
  attach tracepoints, or access privileged
  BPF program types.
- Both tracefs directory paths were listed
  successfully. The available events,
  their format files, tracefs mounting details,
  and actual event-read permissions
  have **not** yet been assessed.
  Directory listings and GID membership
  are distinct from authorization to
  enable tracing or install new probes.

### Optional final observation-only event listing

Inspect only existing event names and one scheduler
tracepoint format. Do **not** modify `tracing_on`,
`set_event`, `events/*/enable`, perf/sysctl values,
or load BPF programs.

```bash
adb shell '
for root in /sys/kernel/tracing /sys/kernel/debug/tracing; do
  echo "=== $root ==="
  ls -ldZ "$root" 2>&1
  ls -lZ "$root/available_events" "$root/events/sched/sched_switch/format" 2>&1
  if [ -r "$root/available_events" ]; then
    echo "-- scheduler/locking event names --"
    grep -E "^(sched:|futex:|lock:|workqueue:)" "$root/available_events" | head -n 40
  fi
  if [ -r "$root/events/sched/sched_switch/format" ]; then
    echo "-- scheduler format excerpt --"
    sed -n "1,20p" "$root/events/sched/sched_switch/format"
  fi
  if [ -r "$root/available_events" ]; then break; fi
done
'
```

Further trace/event checks are for **non-destructive
diagnostics only**, not a root or payload
trigger. Current KernelSU v3.2.5 Samsung fallback
needs kprobes/kretprobes, absent from this HXL1
configuration. Signature enforcement, locked
bootloader, Samsung RKP/KDP/DEFEX, and lack of
runtime GhostLock exploitation remain separate
unresolved gates. Keep HXL1 research-only.

---

## October 10: physical shell can read `sched_switch` format but not global event index

The owner executed the **read-only** tracepoint metadata command
on the stock `SM-G986U1` running `G986U1UESCHXL1`.

**Both paths** (`/sys/kernel/tracing` and
`/sys/kernel/debug/tracing`) gave these results:

- `ls -lZ available_events`: **Permission denied**;
  global event enumeration was *not* obtained.
  This output alone does not identify whether DAC,
  SELinux, or another access mechanism denied
  the specific operation.
- `events/sched/sched_switch/format`:
  readable by `uid=2000(shell)`. File appears
  `-r--r--r-- root root u:object_r:debugfs_tracing:s0`.
- Event name `sched_switch`, **ID 56**;
  its byte layout was reported by the original
  kernel metadata and is valid for that original
  tracepoint on this boot.

| Field | Byte offset | Size |
|---|---:|---:|
| `common_type` | 0 | 2 |
| `common_flags` | 2 | 1 |
| `common_preempt_count` | 3 | 1 |
| `common_pid` | 4 | 4 |
| `prev_comm` | 8 | 16 |
| `prev_pid` | 24 | 4 |
| `prev_prio` | 28 | 4 |
| `prev_state` | 32 | 8 |
| `next_comm` | 40 | 16 |
| `next_pid` | 56 | 4 |
| `next_prio` | 60 | 4 |

The listed `sched_switch` fields end at
**byte 64**; this is a known-format metadata
result, **not a live capture**. The shell
command did not read `tracing_on`, `enable`,
`trace_pipe` or the binary ring-buffer records.
It did not attach programs, create probes, change
settings, or trigger a futex/RT-mutex workload.

**Updated status:** read-only individual event-format
access **verified**; global `available_events`
enumeration **denied**; event enabling, live
capture, BPF program load, GhostLock exploit
and Root/KernelSU remain **unverified**.
This closes the existing bounded tracing-permission
inventory. Further trace scans should be driven by
a specific diagnostic question, rather than
mistaken for a new KernelSU hook backend.

---

## Phase 2: benign futex-PI ARM64 prerequisite diagnostic

**Purpose:** answer only whether an unrooted stock
`SM-G986U1` with exact firmware `G986U1UESCHXL1`
can perform *ordinary, uncontended* futex and
futex-PI syscalls. This does **not** attempt
CVE-2026-43499, futex requeue, deadlock-chain
creation, a race, kernel memory changes or root.

The new source is
`research/y2q-G986U1UESCHXL1/futex_pi_smoke.c`.
Its first gate requires the exact Samsung model,
`y2q` device, bootloader build, fingerprint,
`4.19.113-27095354` running kernel release,
locked flash and vbmeta properties, 4096-byte pages,
and an ordinary **ADB shell** UID/EUID 2000.
It refuses other device/firmware/root contexts.

The diagnostic performs five bounded checks once:

1. `FUTEX_WAIT_PRIVATE` against an intentionally
   mismatched value: should return **EAGAIN immediately**;
   it **never blocks on the WAIT call**.
2. `FUTEX_WAKE_PRIVATE` with no waiters: expect zero
   woken.
3. `FUTEX_LOCK_PI_PRIVATE` on a fresh, unlocked,
   thread-private word: expect success and current
   thread ownership.
4. `FUTEX_UNLOCK_PI_PRIVATE` for the acquired word:
   expect successful unlock/reset.
5. `FUTEX_TRYLOCK_PI_PRIVATE` and
   `FUTEX_UNLOCK_PI_PRIVATE` on another fresh word:
   expect success and reset.

Only one thread/process is used; **there are no
contended locks, PI requeue operations, repeated
races, user-visible sysctl modifications, BPF
attachments, privilege adjustments, or kernel modules**.
PI lock/unlock must be correctly paired, as required
by [futex(2)](https://man7.org/linux/man-pages/man2/futex.2.html).

### Build and artifact

The existing
`.github/workflows/y2q-identity-probe.yml`
runs `tools/test_y2q_futex_pi_smoke.py`,
cross-compiles the new tool with Android API 33,
and uploads artifact named
`y2q-HXL1-futex-pi-smoke-NOT-ROOT`. Download
the artifact from the successful workflow run
of the **investigation branch**, not from an
old job or another repository.
The ZIP contains a single executable
`y2q-HXL1-futex-pi-smoke`.

The local equivalent build command is:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools/test_y2q_futex_pi_smoke.py

# Requires Android NDK r30 for Linux and ANDROID_NDK_HOME.
bash research/y2q-G986U1UESCHXL1/build_futex_pi_smoke.sh
```

Do **not** confuse this diagnostic executable
with the project's inert shared library,
KernelSU `ksud`, an unsigned `.ko`,
or a GhostLock exploit.

### Controlled unrooted S20+ test

After obtaining the built executable locally,
point `BIN` to it. For example, if you built
through the NDK:

```bash
BIN=~/src/Root-My-Galaxy-Payloads/research/y2q-G986U1UESCHXL1/build/y2q-HXL1-futex-pi-smoke
file "$BIN"
sha256sum "$BIN"
adb shell getprop ro.boot.bootloader
adb shell id

# Staging under /data/local/tmp is the ONLY device file write.
adb push "$BIN" /data/local/tmp/y2q-HXL1-futex-pi-smoke
adb shell chmod 700 /data/local/tmp/y2q-HXL1-futex-pi-smoke

# A host-side deadline protects against an unexpected system hang.
timeout --signal=TERM --kill-after=2s 10s \
  adb shell /data/local/tmp/y2q-HXL1-futex-pi-smoke

# Remove staging file after collecting the result.
adb shell rm -f /data/local/tmp/y2q-HXL1-futex-pi-smoke
```

**Run as normal `adb shell`, not `su`.**
If the host deadline fires, collect the exit code
and stop rather than retrying repeatedly.

Expected terminal labels:

- `RESULT=PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY` /
  exit 0: ordinary, uncontended futex-PI
  operations work; **not vulnerability/root proof**.
- `RESULT=INCONCLUSIVE_PI_UNAVAILABLE` /
  exit 3: a PI operation failed with an unavailable/
  permission/unsupported error; report its errno.
- `RESULT=FAIL_STANDARD_FUTEX` or
  `RESULT=FAIL_PI_SEMANTICS` / exit 4:
  unexpected behavior; do not continue on device.
- `RESULT=REFUSED_*` / exit 2:
  guard rejected environment; **do not bypass**.

CI/build and device results must be recorded
independently; **not verified until output
from a successful run is supplied**. This stage
does not inspect the PI requeue/error lifecycle,
so success does not establish the previously
identified GhostLock path's reachability or
exploitability. Do not automate stress/races
or attempt KernelSU insertion on this basis.

---

## Phase 2 WSL automation: one Python command for benign futex-PI diagnostic

`tools/run_y2q_futex_smoke.py` automates the prior
manual build/artifact download, strict preflight,
ADB push, **one-time** unrooted run, clean removal,
and JSON result capture. The diagnostic itself has
an **independent six-second `alarm(6)`** in case
the host-side ADB connection stalls. The host runner
uses a default 12-second subprocess deadline.

After pulling the investigation branch:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m py_compile tools/run_y2q_futex_smoke.py
python3 -m unittest -v tools/test_run_y2q_futex_smoke.py \
  tools/test_y2q_futex_pi_smoke.py

# Confirm exactly one S20+ in state "device":
adb devices

# Full automated flow (does not request root or exploit CVE-2026-43499):
python3 tools/run_y2q_futex_smoke.py
```

The runner obtains the executable in this order:
(1) reuse a local `research/y2q-G986U1UESCHXL1/build/y2q-HXL1-futex-pi-smoke`
if already present;
(2) if `gh` exists, download a **successful GitHub Actions artifact matching the exact local Git HEAD**
from `y2q-identity-probe.yml`;
(3) try a local NDK build if installed under
`ANDROID_NDK_HOME` or a recognized SDK/NDK path.
It refuses a stale CI artifact by default.

To require a fresh CI-matching executable:

```bash
# Requires GitHub CLI installed and logged in.
gh auth status
python3 tools/run_y2q_futex_smoke.py --source actions
```

Or to build with the local Android NDK:

```bash
export ANDROID_NDK_HOME=/path/to/android-sdk/ndk/30.0.16248370
python3 tools/run_y2q_futex_smoke.py --source local
```

Or to use an executable you already downloaded
and extracted manually from the successful workflow:

```bash
python3 tools/run_y2q_futex_smoke.py \
  --binary /path/to/y2q-HXL1-futex-pi-smoke
```

The `--preflight-only` flag validates the binary,
single ADB device, firmware identity, locked
boot state, kernel release, page size, UID=2000
and enforcing SELinux **without uploading/executing**:

```bash
python3 tools/run_y2q_futex_smoke.py --preflight-only
```

If there are multiple attached ADB devices,
pass `--serial SERIAL`. The runner validates
ELF64 little-endian AArch64 PIE header, computes
SHA-256, refuses a pre-existing staged path,
performs only `adb push`/`chmod 700`/one
`adb shell` execution, and removes the exact
sha256-suffixed path using a `finally` cleanup.
It saves output to a timestamped file:

`~/s20-artifacts/y2q-futex-pi-smoke-YYYYMMDDTHHMMSSZ.json`

A successful ordinary-futex-PI result ends with
`RESULT=SAFE_PI_PREREQUISITES_VERIFIED_NOT_ROOT`.
This is **not** a demonstration of the vulnerable
PI-requeue route, privilege escalation, module
loading or KernelSU functionality. Do not retry
a failing/hung test repeatedly.

**Status:** source and workflow wiring committed;
host tests, CI artifact publication and live
S20+ behavior must be verified in the owner's WSL
terminal. No root/security settings or boot image
modifications are authorized by this diagnostic.

---

## October 10, 04:11 UTC — physical HXL1 futex-PI baseline confirmed

The owner ran the committed Phase 2 WSL orchestrator
`python3 tools/run_y2q_futex_smoke.py` with an
installed Android NDK r30 at
`/home/main/opt/android-ndk-r30`.
The Python runner's **7/7 automated tests passed**
(0.016 s), and the Android executable built
successfully as an **AArch64 64-bit PIE** with
Android dynamic linker `/system/bin/linker64`.

**Original binary SHA-256:**
`e7506a3f5ef3f323e278b83ec353354298f7f1c74a6972efbddd3f5b70c54412`

The orchestrator's strict stock HXL1 device, UID 2000,
kernel and SELinux checks succeeded. On-device output:

```text
IDENTITY=EXACT_STOCK_HXL1_ADB_SHELL
CHECK=WAIT_VALUE_MISMATCH STATUS=PASS rc=-1 errno=11
CHECK=WAKE_NO_WAITERS STATUS=PASS rc=0 errno=0
CHECK=LOCK_PI_UNCONTENDED STATUS=PASS lock_rc=0 owner_matches=1 unlock_rc=0 unlock_errno=0 unlocked_zero=1
CHECK=TRYLOCK_PI_UNCONTENDED STATUS=PASS lock_rc=0 owner_matches=1 unlock_rc=0 unlock_errno=0 unlocked_zero=1
RESULT=PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY
NOTE=NOT_GHOSTLOCK_NOT_EXPLOIT_NOT_KERNELSU_NOT_ROOT
```

The runner reported **`RESULT=SAFE_PI_PREREQUISITES_VERIFIED_NOT_ROOT`**,
removed the staged executable and saved a host-side
JSON evidence report at
`/home/main/s20-artifacts/y2q-futex-pi-smoke-20261010T041101Z.json`.

| Physical-device gate | Result |
|---|---|
| Exact HXL1 Android/firmware identity | Pass |
| Ordinary `FUTEX_WAIT_PRIVATE` on mismatched word | Immediate `EAGAIN`; pass |
| `FUTEX_WAKE_PRIVATE` with no waiters | Return zero; pass |
| Fresh-word `FUTEX_LOCK_PI_PRIVATE` and owner unlock | Pass |
| Fresh-word `FUTEX_TRYLOCK_PI_PRIVATE` and owner unlock | Pass |
| No-root staged file cleanup | Pass |
| GhostLock PI-requeue/proxy waiter error path | **Not exercised** |
| Exploit/privilege escalation | **Not demonstrated** |
| Module loader / KernelSU hooks | **Not verified** |
| Matching GitHub Actions run | **Not independently checked** |

**Interpretation:** This verifies a useful physical
prerequisite: a stock `u:r:shell:s0` caller can
issue normal futex wait/wake and uncontended
priority-inheritance lock operations on exact
`G986U1UESCHXL1`. It does **not** establish the
CVE-2026-43499 PI-requeue path is reachable or
exploitable, and says nothing about protected
kernel text, trusted module signing, KernelSU
ABI/hook integration or temporary root.

**Next bounded offline research task:** map the
original Samsung `kernel/futex.c` PI requeue and
`kernel/locking/rtmutex.c` proxy-lock return/error
paths, annotate error/waiter cleanup invariants,
and compare to a known-fixed upstream implementation
on a disposable test kernel. Keep this source-level
and instrumented-lab work separate from the stock
handset; do not attempt a live requeue/error-path
race or treat a kernel crash as progress toward root.
A separate authorized module loading and Linux 4.19
KernelSU hooking compatibility gate still remains.

---

## Phase 3 — isolated ARM64 QEMU Linux 4.19 lab bootstrap

The owner's WSL2 environment was checked on October 10:
`aarch64-linux-gnu-gcc`, `clang`, `make`,
`cpio` and `git` are installed. The original
Samsung `rtmutex.c` and `futex.c` SHA-256 hashes
match exactly. The x86_64 WSL2 host has approximately
**3.8 GiB RAM** and **945 GiB free disk**,
but `qemu-system-aarch64` was **not installed**.

The repo now provides a purely isolated host/VM helper:
`tools/y2q_qemu_lab.py` and the static guest program
`research/y2q-G986U1UESCHXL1/qemu_lab_init.c`.

**This lab is NOT a Samsung firmware VM.**
QEMU's generic ARM64 `virt` board is structurally
different from the Snapdragon 865 Samsung board.
The helper only accepts an **upstream 4.19** kernel
tree, stores all built artifacts outside the original
source at `~/s20-artifacts/qemu-lab`, and refuses
using the original Samsung source as a `virt` kernel.
The guest starts PID 1, prints its ARM64 kernel
version, performs one immediate-return
`FUTEX_WAIT_PRIVATE` value mismatch, prints
`RMG_QEMU_LAB_COMPLETE=PASS_BOOT_ONLY_NOT_GHOSTLOCK`
and powers off. It does **not** exercise any CVE race,
RT-mutex error chain, kernel overwrite, privilege
change, module load or KernelSU hook.

### Setup in Ubuntu WSL2

```bash
sudo apt update
sudo apt install -y qemu-system-arm qemu-utils \
  bc bison flex libssl-dev libelf-dev

cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m py_compile tools/y2q_qemu_lab.py
python3 -m unittest -v tools/test_y2q_qemu_lab.py
python3 tools/y2q_qemu_lab.py check
```

Ubuntu provides `qemu-system-aarch64` through
[`qemu-system-arm`](https://ubuntu.com/server/docs/virtualization-qemu/).

### Acquire a disposable UPSTREAM Linux 4.19 tree

The isolated VM needs a buildable upstream Linux
4.19 baseline, **not** Samsung's original device tree.
Linux
[`4.19.325`](https://cdn.kernel.org/pub/linux/kernel/v4.x/)
is an archived final stable release of that older
kernel series, published December 2024, and is
used as the generic `virt` baseline.
It is **not** claimed to reproduce Samsung's
HXL1 bug or ABI.

```bash
mkdir -p ~/src
cd ~/src
curl --fail --location --retry 3 \
  --output linux-4.19.325.tar.xz \
  https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.19.325.tar.xz
tar -xJf linux-4.19.325.tar.xz

# Do not overwrite or rebuild ~/src/samsung-y2q-hxl1-stock.
cd ~/src/Root-My-Galaxy-Payloads
python3 tools/y2q_qemu_lab.py initramfs
python3 tools/y2q_qemu_lab.py configure
python3 tools/y2q_qemu_lab.py build
python3 tools/y2q_qemu_lab.py boot
```

The helper defaults to **one build job** (maximum
`--jobs 2`), **one vCPU** and **1024 MiB VM RAM**,
using software ARM64 emulation on the x86_64 WSL
host. No disk image or network interface is attached.
Build output goes to
`~/s20-artifacts/qemu-lab/kernel-build.log`.
Guest console logs and JSON reports are written
as `qemu-boot-*.log` and `qemu-boot-*.json`.
VM boot reports **`PASS_BOOT_ONLY`** only if the
guest prints the expected marker without reported
kernel panic/Oops/KASAN BUG. ARM64 QEMU boot and
upstream compilation have **not yet been confirmed
on the owner's machine**.

### Optional separate KASAN/debug build

Once the plain ARM64 boot baseline passes, build a
**separate** KASAN configuration (the `configure`
step replaces only the lab's out-of-tree config):

```bash
python3 tools/y2q_qemu_lab.py configure --kasan
python3 tools/y2q_qemu_lab.py build --jobs 1
python3 tools/y2q_qemu_lab.py boot --memory 1536
```

The helper verifies that `CONFIG_KASAN=y`
and `CONFIG_DEBUG_RT_MUTEXES=y` survive
`olddefconfig`; if the old 4.19 kernel
cannot build with the current host GCC,
that is a compiler/toolchain compatibility
failure—not evidence of Samsung runtime
exploitability. KASAN is instrumentation
for a disposable VM, not a mechanism to
root or modify the phone.

**Next gate:** verify generic `virt` boots first.
Later source/correction comparisons must explicitly
separate upstream and Samsung/vendor semantics.
No exercise involving the GhostLock race or
potentially destabilizing PI requeue operations
belongs on the physical handset. KernelSU module
signature and hook backend gates remain unresolved.

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
