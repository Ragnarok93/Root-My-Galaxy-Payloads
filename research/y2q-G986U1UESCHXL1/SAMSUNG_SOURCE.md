# Matching Samsung Galaxy S20+ (SM-G986U1) HXL1 kernel source

## Exact source archive listed by Samsung

From the Samsung Open Source Release Center's North American Android 13
Galaxy S20+ release listing (models SM-G986U, SM-G986U1, SM-G986W),
the **Description** column includes:

`SM-G986U_13_Opensource_G986USQSCHXL1_G986U1UESCHXL1_G986WVLSCHXL1.zip`


**Owner-reported source download (2026-10-09):** the downloaded file
`D:\root-my-galaxy-test\source\SM-G986U.zip` is a **wrapper containing
13 ZIP archives**, not the exact firmware patch ZIP by itself. Size:
`256918162` bytes. SHA-256:
`940fe6bbcfe3dcd372ad662dd24b56e0a3ba1a965666b04051fe9941bab4986d`.
The base source (`SM-G986U_NA_13_Opensource.zip`; 255083506 bytes) and
HXL1-specific source (`...G986U1UESCHXL1...zip`; 314586 bytes)
are separately nested within the wrapper. The small HXL1 ZIP may be a
delta/overlay; its contents and relationships have not yet been inspected.
Do not assume the newest HYC1 ZIP applies to the HXL1 firmware.

**Target firmware:** `G986U1UESCHXL1`. The full filename explicitly includes
this firmware string, unlike the older revisions also present in the
release list. The top-level **Version** column is not the exact revision
of every cumulative source archive listed under **Description**.

Status:
- [x] Exact firmware token identified in Samsung source package listing
- [x] Wrapper archive downloaded; size and SHA-256 reported by owner
- [x] Wrapper ZIP entries inventoried (13 internal ZIPs)
- [x] Base/U1 DTS/HXL1 inner ZIP hashes and their TAR entries inventoried
- [x] HXL1 TAR fully scanned (59 members); U1 DTS TAR fully scanned (6)
- [x] All 59 HXL1 entries listed: 30 regular source files and 29 directories
- [ ] Determine cumulative firmware-overlay order and source-file provenance
- [x] Full main Kernel.tar.gz scan completed (76,068 members)
- [ ] Compare Samsung defconfigs with extracted running kernel config
- [ ] Kernel Makefile (`VERSION/PATCHLEVEL/SUBLEVEL`) examined
- [ ] Source defconfig and toolchain instructions compared with `config.gz`
- [ ] Exact commit/build provenance assessed against extracted ARM64 kernel
- [ ] Stock kernel build reproduced and differences documented

Do not confuse an exact *filename match* with proof that the kernel
source inside produces a byte-identical kernel. Source may require
proprietary tools, Samsung patches, overlays, or unpublished components.

## Windows 11: get the source onto drive D:

1. Open https://opensource.samsung.com/ in your Windows browser.
2. Search for `SM-G986U1`. Find the group including
   `SM-G986U`, `SM-G986U1`, and `SM-G986W`.
3. Open the corresponding **Source** selection/download control, then
   download the archive whose **full name** matches the HXL1 filename above.
4. Save the ZIP under `D:\root-my-galaxy-test\source\`. Do not rename it,
   extract it into your existing firmware directory, or mix it with
   the AP/BL/CP/CSC Odin images.

You may need to sign in or agree to Samsung's terms on their website.
The archive is not automatically retrievable from an ordinary public
GitHub URL.

## Ubuntu in WSL2: inspect the actual ZIP-in-ZIP packaging

The Windows D: drive is mounted under `/mnt/d` in the existing WSL
environment. Open Ubuntu and run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

SOURCE_ZIP="/mnt/d/root-my-galaxy-test/source/SM-G986U.zip"

python3 tools/inspect_samsung_source.py "$SOURCE_ZIP" \
    --json ~/s20-artifacts/samsung-source-inventory.json
```

The tool now understands ZIPs nested within Samsung's outer release ZIP.
First inspect **only the HXL1 and U1-specific DTS** packages:

```bash
python3 tools/inspect_samsung_source.py "$SOURCE_ZIP" \
    --scan-nested \
    --select-zip-regex 'G986U1UESCHXL1|SM-G986U1_NA_13_Opensource_dts' \
    --json ~/s20-artifacts/samsung-hxl1-inventory.json
```

Then inspect the **large shared base source** package, which may contain
further nested TARs:

```bash
python3 tools/inspect_samsung_source.py "$SOURCE_ZIP" \
    --scan-nested --max-tar-members 20000 \
    --select-zip-regex '^SM-G986U_NA_13_Opensource[.]zip$' \
    --json ~/s20-artifacts/samsung-base-inventory.json
```

These actions never extract files into the working source directory or
execute code from the package. The tool may spool the inner 255 MB ZIP
to an automatically deleted temporary file because Python's ZIP
reader requires seeking, so **have ~300 MB of free temporary disk space**.
Nested ZIPs are capped by default at 512 MiB per archive, and TAR
traversal is capped at 20,000 members. If a scan reports a limit
or error, do not infer any absent source files from that incomplete scan.

The inventories print SHA-256 for every scanned inner ZIP, allowing
the specific HXL1 package and base-source bytes to be tracked
independently of the outer wrapper.

## October 9, 2026: observed nested package results

The Samsung wrapper SHA-256 is verified by the owner's local inspection.
The three separately scanned nested ZIPs were:

| Archive | SHA-256 | Observation |
| --- | --- | --- |
| `SM-G986U_NA_13_Opensource.zip` | `23011b7641701e4542f3a0b212eb5aca6a2f9ea4f14cee3b64f46dcf0cb1bfc7` | Contains `Kernel.tar.gz` and `Platform.tar.gz`; kernel scan **truncated at 20,000 entries** |
| `SM-G986U1_NA_13_Opensource_dts.zip` | `51b2099dc5d5dc658a8519026be1b1e6aa0088efc35af176831a67228619c7ae` | Contains 6-member `G986U1UES8HXA1_kernel.tar.gz` with `Kernel/arch/arm64/configs/vendor/y2q_usa_openw_defconfig` |
| `SM-G986U_13_Opensource_G986USQSCHXL1_G986U1UESCHXL1_G986WVLSCHXL1.zip` | `c7fcbabd46ddb9aa0aaa6f396bb68651ecaa42d963d3f2397c93872e3602d7c3` | Contains 59-member `G986USQSCHXL1_kernel.tar.gz` |

The HXL1 TAR being small suggests firmware-specific changes, but
we must inventory its entire contents before deciding whether it is
a patch, replacement set, or supplement. The U1 DTS TAR filename
contains `8HXA1`; its reuse on HXL1 is plausible, but not yet
proven to be valid for the exact running hardware.

### Inspect all 59 HXL1 files and the six U1 DTS files

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

SOURCE_ZIP=/mnt/d/root-my-galaxy-test/source/SM-G986U.zip

python3 tools/inspect_samsung_source.py "$SOURCE_ZIP" \
  --scan-nested \
  --select-zip-regex 'G986U1UESCHXL1|SM-G986U1_NA_13_Opensource_dts' \
  --tar-path-regex '.*' \
  --max-matched-paths 120 \
  --json ~/s20-artifacts/samsung-hxl1-paths.json
```

### Inspect the entire main kernel source TAR and locate defconfigs

```bash
python3 tools/inspect_samsung_source.py "$SOURCE_ZIP" \
  --scan-nested \
  --select-zip-regex '^SM-G986U_NA_13_Opensource[.]zip$' \
  --max-tar-members 200000 \
  --tar-path-regex '(^(\./)?Makefile$|^Kernel/Makefile$|(^|/)arch/arm64/configs/vendor/.*(y2q|kona).*defconfig$)' \
  --max-matched-paths 120 \
  --json ~/s20-artifacts/samsung-base-paths.json
```

These are inventories, not kernel builds. If the main TAR
still reports `limitReached: True`, raise the member cap only
after checking available CPU/disk resources. The ZIP inspector
spools compressed source data to a temporary file and does not
persistently unpack either kernel tree.

## October 9: full inventory confirms HXL1 source override set

The owner ran the updated full TAR inventory:

- Shared main kernel TAR: **76,068** total entries, `limitReached=False`.
- Main kernel Makefile: `./Makefile` (**65,984 bytes**, just above the
  inspector's former 64-KiB text-reading limit; fixed to 256 KiB).
- Shared base source config: `./arch/arm64/configs/vendor/y2q_usa_singlew_defconfig`
  (**190,565 bytes**).
- U1 DTS config: `Kernel/arch/arm64/configs/vendor/y2q_usa_openw_defconfig`
  (**190,565 bytes**). Equal file sizes are not proof of identical contents.
- HXL1 firmware TAR: **59** entries, including **30** C/header files,
  with the remaining **29** entries being directories.

The HXL1 source files affect GPU KGSL, USB notify, Linux networking,
SDP, HID, IOMMU, MHI, Qualcomm SMEM, DSP/RPC, UVC and USB audio.
No root or module-loading capability is implied by these changes.

### Compare stock kernel configuration and source-update provenance

The next read-only research tool audits individual Samsung incremental
update ZIPs **through HXL1**, retaining their archive listing order,
and records which update last changed each source filename. It **does not**
apply patches or generate a boot image. Any proposed overlay order must
still be checked against Samsung's build README/provenance.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/audit_samsung_kernel_layers.py \
  /mnt/d/root-my-galaxy-test/source/SM-G986U.zip \
  --target-firmware G986U1UESCHXL1 \
  --device-config-gz ~/s20-artifacts/config.gz \
  --json ~/s20-artifacts/samsung-hxl1-source-audit.json
```

The output reports:

- Version/patchlevel/sublevel parsed from Samsung's base kernel Makefile.
- SHA-256 of the base Makefile and both singlew/openw defconfigs.
- Explicit config differences between each source defconfig and the
  running device's extracted kernel `config.gz`. These are **pre-Kconfig**
  comparisons; differences alone do not prove a broken or wrong build.
- Per-update source-file counts, repeated names and which updates
  contain files not repeated in the final HXL1 update ZIP.
- Exclusion of later HYC1 source updates from the HXL1 target build.

This is the next evidence gate before assembling or building stock kernel source.

## October 9: provenance audit confirms configuration compatibility

Owner-reported audit through firmware `G986U1UESCHXL1`:

- Shared Samsung source kernel: `VERSION=4`, `PATCHLEVEL=19`,
  `SUBLEVEL=113`, agreeing with running `4.19.113-27095354`.
- Base `y2q_usa_singlew_defconfig` SHA-256:
  `61f109752d3c91a5167dddcb05f79707f04f09edd2d4161a384fefa6fa35b5b8`.
- U1-specific `y2q_usa_openw_defconfig` SHA-256:
  `61f109752d3c91a5167dddcb05f79707f04f09edd2d4161a384fefa6fa35b5b8`.
  **These two files have identical bytes, despite differing filenames.**
- **5,799 matching explicit config values, 0 differing,
  0 explicit symbols missing** when either defconfig is compared against
  the extracted live kernel configuration (`config.gz`).
- 11 selected ZIPs: base + U1 device tree + **nine** chronological
  source-revision archives through HXL1. Later HYC1 excluded.
- **40 distinct source paths** changed across these updates. **10** paths
  modified before HXL1 are **not** repeated in the final HXL1 ZIP.
  A naive base+HXL1-only assembly is therefore not a faithful source
  reconstruction.
- The original Makefile's blank `EXTRAVERSION =` was previously
  misparsed by a cross-newline regex as `NAME = "People's Front"`.
  The parser has been fixed; it does not indicate an extra kernel suffix.

**Important limitation:** ZIP listing order was used as an assumed
incremental apply order. It has NOT yet been confirmed by Samsung's
build README. While strong, an identical defconfig does not prove
binary identity of the resulting kernel or an installable image.

### Next: read Samsung's own release/build instructions

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/audit_samsung_kernel_layers.py \
  /mnt/d/root-my-galaxy-test/source/SM-G986U.zip \
  --target-firmware G986U1UESCHXL1 \
  --device-config-gz ~/s20-artifacts/config.gz \
  --show-readme \
  --json ~/s20-artifacts/samsung-hxl1-source-audit-with-readmes.json \
  > ~/s20-artifacts/samsung-hxl1-instructions.txt

grep -nE '^===== (README:|END README)' \
  ~/s20-artifacts/samsung-hxl1-instructions.txt
```

Review the blocks bounded by `===== README: ... =====` and
`===== END README =====` in the text report. You can inspect it with:

```bash
less ~/s20-artifacts/samsung-hxl1-instructions.txt
```

Extract only the needed readme text to share (do not paste the
long SHA-256 and update list again). Confirming Samsung's intended
update integration steps is the final prerequisite to a
**stock-only, off-device** source assembly and build attempt.

## Reconstructing a stock HXL1 kernel source tree — experimental/off-device

The main release's `README_Kernel.txt` gives a base kernel build recipe,
not an explicit application order for firmware-specific source updates.
It documents:

- Cross-compile architecture: `ARCH=arm64`
- Target config: `vendor/y2q_usa_singlew_defconfig`
- Qualcomm `llvm-arm-toolchain-ship/10.0/bin/clang`
- `aarch64-linux-android-4.9` GCC supporting toolchain
- `CLANG_TRIPLE=aarch64-linux-gnu-`, `DTC_EXT=tools/dtc`,
  `CONFIG_BUILD_ARM64_DT_OVERLAY=y`, and out-of-tree `O=out`
- Result: `arch/arm64/boot/Image` and any `.ko` modules.

The original proprietary toolchain has **not** been located or reproduced.
The NDK r30 used for a read-only Android userspace ELF is a newer, distinct
toolchain; do not label an NDK kernel build as bit-identical.

### Safety and source provenance assumptions

Samsung's inner ZIPs contain base kernel source, U1-specific device config
and incremental source replacement TARs. The release README **does not
explicitly document their assembly order**. The candidate assembler uses
the release wrapper's listed order only **through HXL1**, never HYC1. It
requires an explicit experimental opt-in. The tool:

1. Requires the exact known SHA-256 of the 256,918,162-byte owner-provided
   `SM-G986U.zip` wrapper.
2. Uses the JSON source audit to select and individually hash-check
   11 internal ZIPs.
3. Restores **only kernel source**, not the unrelated `Platform.tar.gz`.
4. Rejects TAR traversal, escaping symlinks, special device entries,
   existing output destinations and unexpected changes of inner ZIP hashes.
5. Applies 9 sets of replacement source files with no binary modifications.
6. Checks the final SHA-256 hashes of all **40** changed source paths.
7. Writes an external provenance manifest, with source build/boot verification
   explicitly remaining **open**.

Allow at least **3 GiB free** in Ubuntu's Linux filesystem, preferably
more. Source tree reconstruction can write significantly more than the
256.9 MB compressed wrapper. Use a path under `~/src`, **not** on `/mnt/d`.
The tool does not communicate with the phone, compile a root payload,
write a boot image or run Odin/fastboot.

### Phase A: verify source inputs only (default)

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
df -h ~

python3 tools/assemble_samsung_stock_kernel.py \
  /mnt/d/root-my-galaxy-test/source/SM-G986U.zip \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --output ~/src/samsung-y2q-hxl1-stock \
  --json ~/s20-artifacts/samsung-hxl1-assembly-preflight.json
```

Expected: `Mode: PREFLIGHT ONLY`; the command should not create
`~/src/samsung-y2q-hxl1-stock`. If it rejects the archive, do not
bypass integrity checks.

### Phase B: assemble the candidate stock source

Only after accepting that the firmware-update order remains an
**inference**, invoke this explicit opt-in:

```bash
python3 tools/assemble_samsung_stock_kernel.py \
  /mnt/d/root-my-galaxy-test/source/SM-G986U.zip \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --output ~/src/samsung-y2q-hxl1-stock \
  --assemble-experimental \
  --json ~/s20-artifacts/samsung-hxl1-assembly-report.json
```

Expected:
- Candidate output `~/src/samsung-y2q-hxl1-stock/`
- Manifest `~/src/samsung-y2q-hxl1-stock.source-manifest.json`
- `Verified final overlay source files: 40`

Failure produces an explicit staging path (`.s20-hxl1-stage-*`) for
inspection and manual removal. The tool never clears existing output
automatically.

### Phase C: validate unmodified source before building

Verify the resulting source version and configuration against the audit:

```bash
cd ~/src/samsung-y2q-hxl1-stock
sed -n '1,12p' Makefile
sha256sum arch/arm64/configs/vendor/y2q_usa_singlew_defconfig \
  arch/arm64/configs/vendor/y2q_usa_openw_defconfig
test ! -e out && echo 'No kernel build output yet'
```

Next verify available original Clang 10/GCC 4.9 or document deviations
before even attempting a stock kernel build. **Do not flash the output.**

## October 9: owner-side stock source reconstruction passed

The owner completed preflight with the exact `SM-G986U.zip` wrapper hash,
then ran experimental source assembly in WSL2:

- Reconstructed output: `/home/main/src/samsung-y2q-hxl1-stock`
- 11 Samsung release source layers processed through HXL1
- SHA-256 verified for **all 40** final firmware-overlay files
- Atomic final output directory created, external manifest written
- **No kernel compile, bootloader change, image flashing, or root test**
- Caveat: applying incrementals in Samsung's ZIP listing order is an
  explicitly recorded reconstruction assumption, not a README guarantee

The root filesystem showed 950 GiB available before assembly.

### Next: check source integrity and compiler readiness without building

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/preflight_samsung_stock_build.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --json ~/s20-artifacts/samsung-hxl1-build-preflight.json
```

This checks the kernel Makefile version, both 190,565-byte Samsung
defconfig fingerprints, all 40 verified overlay files, the assembly
manifest, and the availability/versions of common kernel host tools.
It **does not** build or change anything in the source directory.

Original Samsung's README mentions Qualcomm's
`llvm-arm-toolchain-ship/10.0/bin/clang` plus
`aarch64-linux-android-4.9` GCC. Those versions may not be installed
in Ubuntu. The current NDK r30 userspace LLVM used for the read-only
diagnostic is a **much newer toolchain and cannot establish a faithful
Samsung stock-kernel build**.

When the preflight identifies missing host build prerequisites, the
following Ubuntu packages are normal starting points, though this
does not install the needed matching Clang/GCC cross-toolchains:

```bash
sudo apt update
sudo apt install -y build-essential bc bison flex libssl-dev libelf-dev \
  cpio rsync python3 dwarves device-tree-compiler
```

Locate a compatible original-era Clang and GCC cross-compiler, record
their source revisions and hashes, and evaluate the Makefile's explicit
`REAL_CC`/`CROSS_COMPILE`/`CLANG_TRIPLE` requirements before compiling.
For context, Google maintains public historical AOSP Clang and GCC
prebuilt repositories, but they are **not guaranteed** to reproduce
Qualcomm's proprietary 10.0 compiler:
- https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/
- https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/

## First Kconfig compatibility trial (modern toolchain, no kernel build)

The owner confirmed that the following WSL2 tools are available:

- Ubuntu Clang 18.1.3 (`/usr/bin/clang`)
- AArch64 GCC 13.3.0 (`/usr/bin/aarch64-linux-gnu-gcc`)
- AArch64 GNU binutils 2.42 (`/usr/bin/aarch64-linux-gnu-ld`)
- Flex 2.6.4, Bison 3.8.2, Pahole 1.25, host Make 4.3
- Samsung source-local DTC `tools/dtc` version 1.4.4-Android-build

The Samsung Makefile assigns
`REAL_CC = $(srctree)/toolchain/llvm-arm-toolchain-ship/10.0/bin/clang`
and uses `scripts/gcc-wrapper.py`. The historical Qualcomm compiler and
Android GCC 4.9 cross-toolchain remain unverified/unavailable. A
**configuration-only** compatibility trial can run with the modern tools,
without claiming a factory-equivalent kernel binary.

After pulling the latest project changes, run a dry-run first:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/configure_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --json ~/s20-artifacts/samsung-hxl1-config-preflight.json
```

The dry-run verifies all 40 overlay hashes, both stock defconfig hashes,
and the source Makefile version. It rejects an existing output directory
rather than mixing builds.

To generate the stock `.config` with **no Image/DTB/module compile**,
repeat with the `--execute` flag and a separate JSON filename:

```bash
python3 tools/configure_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --execute \
  --json ~/s20-artifacts/samsung-hxl1-config-result.json
```

Expected output includes `SUCCESS: standalone Kconfig generated; kernel
compilation NOT started.` If Make exits nonzero, preserve the output
directory and report the error. The tool never flashes or loads anything
onto the phone.

AOSP's [Clang prebuilts README](https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+/refs/heads/android11-qpr3-release/)
identifies `clang-r370808` as an Android 4.19 kernel compiler,
and the same branch contains that compiler's files. It is a relevant
**historical toolchain candidate**, not proof that Samsung's Qualcomm
10.0 compiler produces matching binaries. The
[AOSP GCC 4.9 prebuilt repository](https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/)
has historical branches; its latest head removed GCC 4.9 binaries.
Do not use the unpinned repository HEAD as an original GCC 4.9 binary.

## October 9: first Kconfig trial reached host build, failed on missing `python`

The owner ran `tools/configure_samsung_stock_kernel.py --execute` using
Ubuntu Clang 18, AArch64 GCC 13, and the verified 11-layer stock HXL1
source tree. The tool successfully invoked GNU Make and built
`scripts/basic/fixdep` and `scripts/kconfig/conf`, but the Samsung
4.19 shell scripts attempted to call `python` (unversioned) and Ubuntu
24.04 had only `python3`. These errors preceded the Kconfig parser's
`init/Kconfig:17: syntax error`. We cannot conclude a standalone
Kconfig incompatibility until the missing Python executable is fixed.

The original source tree and firmware remain untouched. The failed
generated output is preserved at:

`~/src/samsung-y2q-hxl1-config-clang18`

The tool's first-attempt JSON is:

`~/s20-artifacts/samsung-hxl1-config-result.json`

### Fix Python compatibility and safely retry the same Kconfig command

```bash
sudo apt install -y python-is-python3
python --version

cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/configure_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --execute \
  --resume-from-report ~/s20-artifacts/samsung-hxl1-config-result.json \
  --json ~/s20-artifacts/samsung-hxl1-config-retry.json
```

The explicit retry is permitted **only** if the original failed JSON
matches the same source, output, command, and target and the expected
partial Kconfig build files exist without a generated `.config`. The
command reruns `vendor/y2q_usa_singlew_defconfig` only: no Image,
DTB, modules, signing, rooting, or flashing.

If the Kconfig error persists after the missing `python` is resolved,
inspect the generated compiler version and only the relevant diagnostics,
without changing the assembled official source:

```bash
sed -n '12,22p' ~/src/samsung-y2q-hxl1-stock/init/Kconfig
sed -n '1,42p' ~/src/samsung-y2q-hxl1-stock/scripts/gcc-version.sh
```

Warnings in `drivers/gps/Kconfig` and `drivers/perf_mgr/Kconfig`
are recorded, but do not by themselves establish that the 40 file
overlays or the 5,799 config symbols are wrong.

## October 9: stock Kconfig successfully generated with Clang 18

Owner-side configuration retry of the reconstructed, 40/40 hash-verified
HXL1 source was successful after installing Ubuntu's
`python-is-python3` package. The command:

- Ran `vendor/y2q_usa_singlew_defconfig` with
  `REAL_CC=/usr/lib/llvm-18/bin/clang` and
  `CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-`.
- Created the 186-KiB
  `/home/main/src/samsung-y2q-hxl1-config-clang18/.config`.
- Printed `configuration written to .config` and returned successfully.
- Left remaining nonfatal Kconfig warnings in GPS, LEDs,
  security debug and performance manager portions of the vendor source.
- **Did not compile kernel Image, modules or DTBs; did not flash device.**

The next gate is to compare the **generated** configuration (which may
have Kconfig-driven defaults) against the **running device's** verified
`config.gz`. The previous 5,799 exact matches concerned the Samsung
*input defconfig*, not this freshly generated output.

### Compare generated and live kernel configurations

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/compare_samsung_kernel_configs.py \
  --generated ~/src/samsung-y2q-hxl1-config-clang18/.config \
  --running-config-gz ~/s20-artifacts/config.gz \
  --source-defconfig ~/src/samsung-y2q-hxl1-stock/arch/arm64/configs/vendor/y2q_usa_singlew_defconfig \
  --json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json
```

The comparator validates the known original `config.gz` SHA-256 and the
source defconfig SHA-256, then prints:

- Explicit symbol matches and differing values between generated and live config.
- Generated-only and running-only symbol counts.
- Source defconfig versus generated config changes.
- Qualcomm Kona/ARM64, module-signature enforcement, KDP/RKP, DEFEX
  and other important platform/security settings.
- Full difference inventory in JSON, while console examples are limited.

Absent symbols are **not** treated as disabled automatically. The
comparison does not assert bootability or binary identity.

Do not begin a stock Image compilation until any important config
differences have been understood and the original compiler discrepancy
has been recorded.

## October 9: generated Kconfig matches running device except compiler version

Owner-reported output from `tools/compare_samsung_kernel_configs.py`:

- Generated file:
  `~/src/samsung-y2q-hxl1-config-clang18/.config`
- SHA-256:
  `97cf1d93f86251294951ff235e76281e9e3705d5745be6b44f130fc3aa501c09`
- 5,790 shared symbols with exactly matching values, **one different
  explicit value**:
  `CONFIG_CLANG_VERSION=180103` (generated Ubuntu Clang 18) versus
  `CONFIG_CLANG_VERSION=100006` (running Samsung Clang 10.0.6).
- Zero generated-only symbols; 18 running-only symbols, all listed
  as hardware-model or Samsung project identifiers (e.g. Y2Q
  alternative region selectors). They remain unverified for exact
  release fidelity; absent does **not** mean disabled.
- Original source defconfig against generated config: 5,790 matching
  explicit values, 1 compiler-version difference, 8 source-only.
- All 15 compared ARM64/Qualcomm/Kona/Samsung security, module-signature
  and synchronization symbols match the running device.

This is compelling for a **research-only compilation attempt**, not
an exact reconstruction of the OEM executable or a method to load a
custom kernel on a locked bootloader.

### First isolated stock Image compilation — guarded compatibility trial

The included `tools/build_samsung_stock_kernel.py` tool defaults to
**dry run** and enforces:

- Source Makefile SHA-256 from the owner's Samsung base archive.
- SHA-256 of the known, successful generated `.config`.
- Exact reference to the user's full generated-vs-running comparison,
  accepting only the documented `CONFIG_CLANG_VERSION` mismatch,
  rejecting changes to all 15 security/platform symbols.
- Base kernel version, both defconfig digests, and SHA-256 checks
  of all 40 HXL1 source overlays.
- Existing isolated `O=` output directory, original source untouched.
- Explicit `--execute`, separate log file, no output Image already
  present, and no signed/flashable image generation.

The modern Ubuntu GCC 13/Clang 18 environment is a **compatibility
experiment**, not the original Qualcomm GCC 4.9/Clang 10 build.

Dry run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --jobs 2 \
  --json ~/s20-artifacts/samsung-hxl1-image-preflight.json
```

Only after a successful dry run, compile `Image` off-device with
a **fresh, exclusively named log and report**:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report.json
```

The actual compile can fail on modern compiler version, old Kbuild
scripts, dependencies, assembly or linker differences. Failure is
valuable evidence and does not imply a corrupt source archive.
Retain the log, which records the full Make output and exit status.
If unsuccessful, use:

```bash
grep -nE '(^|[[:space:]])(error:|Error [0-9]+|fatal error:|undefined reference)' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build.log | head -60
tail -n 90 ~/s20-artifacts/samsung-hxl1-image-clang18-build.log
```

If the command succeeds, the tool records the compiled `Image` size,
SHA-256 and path, but the binary remains **unsigned, unbooted,
and nonflashable on the owner's currently locked device**.

## October 9: first Image build reaches scripts, blocked by missing Python 2

Owner ran the guarded `Image` build using Ubuntu Clang 18.1.3 / GCC 13.3.0.
Generated Kconfig was still SHA-256 verified, but Make returned 2 before
building a kernel image. The first material failure was:

```text
/usr/bin/env: ‘python2’: No such file or directory
  CC      scripts/mod/empty.o
make[3]: *** [scripts/Makefile.build:339: scripts/mod/empty.o] Error 127
```

Make also printed `make[1]: secgetspf: No such file or directory`
and a warning that the assembler's `.inst` handling may produce
unreliable disassembly. Those are **separate diagnostics**.
We have **not** established that `secgetspf` is mandatory, and should
inspect the actual Makefile reference before substituting a fake program
or changing firmware feature values.

- Failed build log: `~/s20-artifacts/samsung-hxl1-image-clang18-build.log`
- Failed result JSON: `~/s20-artifacts/samsung-hxl1-image-clang18-report.json`
- The partial `O=` output directory must **not be deleted**.
- The original Samsung kernel source has not been edited or flashed.

### Read-only inspect the additional build dependencies

```bash
SRC=~/src/samsung-y2q-hxl1-stock
grep -n -C 6 'secgetspf' "$SRC/Makefile"
grep -RInE '^#!.*python2|/usr/bin/env python2' "$SRC/scripts" \
  "$SRC/arch/arm64" | head -60
sed -n '1,75p' "$SRC/scripts/gcc-wrapper.py"
```

The build scripts are from a kernel originally built against **Python 2**.
Ubuntu 24.04's `python-is-python3` provides `python` but does not
provide `python2`. Do **not** symlink `python2` to Python 3.
The final Python 2 release (2.7.18) is end-of-life and should be
kept isolated and used only for this historical build. See
https://www.python.org/downloads/release/python-2718/.

### Set up isolated genuine Python 2.7.18 in WSL2

Build official CPython source into a **user-owned** directory rather
than overwriting Ubuntu's `/usr/bin/python`. The published source
checksum below is also recorded by Buildroot's 2020 package update:
https://lists.buildroot.org/pipermail/buildroot/2020-April/268853.html.

```bash
sudo apt install -y curl xz-utils build-essential \
  zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
  libffi-dev libncursesw5-dev

mkdir -p ~/src/legacy-toolchains
cd ~/src/legacy-toolchains

curl --fail --location --proto '=https' --tlsv1.2 \
  https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tar.xz \
  --output Python-2.7.18.tar.xz

echo 'b62c0e7937551d0cc02b8fd5cb0f544f9405bafc9a54d3808ed4594812edef43  Python-2.7.18.tar.xz' \
  | sha256sum -c -

tar -xf Python-2.7.18.tar.xz
cd Python-2.7.18

CFLAGS='-std=gnu11' ./configure \
  --prefix="$HOME/opt/samsung-kernel-python2" \
  --without-ensurepip

make -j2
make altinstall
ln -s python2.7 ~/opt/samsung-kernel-python2/bin/python2

~/opt/samsung-kernel-python2/bin/python2 --version
```

No root access is needed beyond installing standard Ubuntu build
dependencies. **Do not install Python 2 globally or use it for web
browsing / application packages.** The interpreter exists only for
these historical kernel compilation scripts.

If Python 2 source building fails on modern GCC/OpenSSL,
record the errors instead of bypassing the SHA-256 check or installing
old Ubuntu packages directly from obsolete distributions.

### Retry the same Image build with a process-local Python 2 PATH

The build tool validates that the supplied `--python2` path executes
a **real Python 2.7**. It prepends the interpreter directory to the
Make subprocess PATH only, without changing the user's global shell
or Samsung source tree.

Use **fresh filenames** because the failed run's log/report are
intentionally immutable:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-02.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-02.json
```

The tool will still reject modified source/config checksums or
preexisting `Image` outputs. More errors may emerge after the missing
Python 2 dependency is resolved; the resulting logs will identify them.

## What we will compare

1. Source `Makefile` version versus the device's `4.19.113-27095354`.
2. SoC/build configuration for Qualcomm Kona / Snapdragon 865.
3. Build setup and supported compiler versus the original `Clang 10.0.6`.
4. Samsung `CONFIG_UH_RKP`, `CONFIG_KDP_*`,
   `CONFIG_SECURITY_DEFEX` and signature enforcement.
5. Any source-specific defconfig against the exact exported running config
   at `~/s20-artifacts/config.gz` (SHA-256
   `1931b2c99e1dad26e93013eac8442384368e7bcde313443ba44baa65d4c053cd`).
6. Source provenance and third-party/redistribution notices.

The support feed **must remain unchanged**: no vulnerability or KernelSU
installation method has been verified for this locked SM-G986U1.
