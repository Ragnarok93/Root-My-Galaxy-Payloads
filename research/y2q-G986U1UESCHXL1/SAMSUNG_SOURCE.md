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

## October 9: second stock Image attempt — CFP compiler routing discrepancy

After installing the isolated `python2` interpreter, the owner's
Clang 18 compatibility build progressed beyond the Python 2
failure, compiling part of the host-side SELinux support, before
hitting:

```text
CC      scripts/mod/empty.o
.../toolchain/llvm-arm-toolchain-ship/10.0/bin/clang:No such file or directory
Is your PATH set correctly?
```

This occurred **despite** passing
`REAL_CC=/usr/lib/llvm-18/bin/clang`, strongly suggesting a
separate compiler route. The Samsung Makefile inspection previously
found:

- Line 373: `REAL_CC = $(srctree)/toolchain/llvm-arm-toolchain-ship/10.0/bin/clang`
- Line 394: `CC = $(PYTHON) $(srctree)/scripts/gcc-wrapper.py $(REAL_CC)`
- Line 795: `CC = $(srctree)/scripts/gcc-wrapper.py $(CFP_CC)`

The later `CFP_CC` wrapper selection is a plausible reason that
`REAL_CC` alone did not replace Samsung's original, unavailable
compiler. The guarded build tool now passes **both**
`REAL_CC=<selected Clang>` and `CFP_CC=<selected Clang>` on the
Make command line, without modifying any files in the Samsung
source tree. Exact Makefile control-flow is still being validated.

To inspect the relevant variable definitions on the owner's actual
stock source:

```bash
grep -nE 'CFP_CC|REAL_CC|secgetspf|scripts/gcc-wrapper.py' \
  ~/src/samsung-y2q-hxl1-stock/Makefile | head -70
sed -n '775,805p' ~/src/samsung-y2q-hxl1-stock/Makefile
```

The warning `secgetspf: No such file or directory` remains.
Other published Samsung kernel Makefiles invoke it in a
`$(shell secgetspf ...)` feature-version check; absence produces
a diagnostic but does not necessarily stop the kernel Make target.
Do not install a dummy helper or change Samsung security configs.

The second failed Image build is retained in:

- `~/s20-artifacts/samsung-hxl1-image-clang18-build-02.log`
- `~/s20-artifacts/samsung-hxl1-image-clang18-report-02.json`

### Third guarded off-device build (both compiler routes)

The isolated Python 2.7.18 prefix is already installed. Pull the
updated utility and first validate the plan; it should print
**both** `REAL_CC` and `CFP_CC` pointing to Clang 18.

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
  --jobs 2
```

If the dry run succeeds:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --jobs 2 --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-03.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-03.json
```

No stock source changes, boot image, signing or flashing. The
next failure (if any) should be assessed from `-03.log`.
The Clang 18 / GCC 13 pairing remains a compatibility
experiment rather than Samsung's factory Clang 10.0.6 / GCC 4.9 build.

## October 9: third Image build — Clang chose native host assembler

The owner tested the guarded third build with
`REAL_CC=/usr/lib/llvm-18/bin/clang` and
`CFP_CC=/usr/lib/llvm-18/bin/clang`. The old Qualcomm Clang
path and Python 2 blockers were resolved, but Make failed during
`scripts/mod/empty.o` with:

```text
/usr/bin/as: unrecognized option '-EL'
clang: error: assembler command failed with exit code 1
```

This means Clang's external assembler route selected the native host
`/usr/bin/as` rather than the GNU ARM64 cross assembler
`/usr/bin/aarch64-linux-gnu-as`. The warning about broken `.inst`
handling and the missing optional `secgetspf` persisted, but neither
was the fatal diagnostic in this attempt.

The build tool now has an **opt-in** `--external-arm64-as` mode
that does not modify the original Samsung source or generated
`.config`. It verifies the external assembler selected by Clang
using a non-compiling `-###` probe with flags:

- `--target=aarch64-linux-gnu`
- `-no-integrated-as`
- `-B/usr/bin/aarch64-linux-gnu-`
- `-EL`

The `-B` argument is a **tool-prefix path** so the external driver
can resolve `aarch64-linux-gnu-as` instead of native `as`. A passing
probe verifies the exact intended ARM64 assembler path appears in
the compiler driver output. The tool also passes
`KCFLAGS=--target=aarch64-linux-gnu -B/usr/bin/aarch64-linux-gnu-`
and a matching `KAFLAGS` in the Make command; these apply only
to generated build commands, not source/defconfig contents.
`--verbose` prints `V=1` compiler invocations into the build log
for diagnosis if the next incompatibility appears.

Verify the cross assembler exists:

```bash
command -v aarch64-linux-gnu-as
aarch64-linux-gnu-as --version | head -1
```

Then use **new** log/report filenames for the fourth stock-only test.
First run a dry-run that checks the assembler's Clang route:

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
  --external-arm64-as \
  --verbose \
  --jobs 2
```

If dry run confirms an AArch64 assembler and finishes successfully:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --external-arm64-as \
  --verbose \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-04.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-04.json
```

If Make fails, send:

```bash
grep -nE 'error:|fatal error:|Error [0-9]+|No such file|unrecognized option' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build-04.log | head -80
tail -n 85 ~/s20-artifacts/samsung-hxl1-image-clang18-build-04.log
```

This is an experimental **off-device** stock-kernel compatibility
build. Nothing is signed, flashed, booted, or installed onto
the locked Galaxy S20+.

## October 9: fourth Image build failed — Samsung Clang prefix overrides cross assembler

Fourth owner-side attempt used the prior
`--external-arm64-as --verbose` build mode. The actual verbose C
compiler invocation retained all of:

- `--target=aarch64-linux-gnu`
- `--prefix=/usr/bin/` (Samsung Kbuild-supplied)
- `-no-integrated-as` (Samsung Kbuild-supplied)
- `-B/usr/bin/aarch64-linux-gnu-` (our attempted routing override)

Despite the `-B` flag, Clang still launched native `/usr/bin/as`,
which failed on ARM64 option `-EL` when compiling
`scripts/mod/empty.o`. The prior probe was insufficient because it did
**not** replicate Samsung's `--prefix=/usr/bin/` argument. This is now
corrected: external assembler routing only passes preflight when the
**full vendor-like flags** select the precise cross assembler executable.

### Fifth compatibility trial: verified Clang integrated ARM64 assembler

Clang also includes an AArch64 *integrated assembler*. Adding
`-integrated-as` **after** the original `-no-integrated-as`
overrides the external assembler request, bypassing `/usr/bin/as`
entirely. The build helper now offers an **opt-in**
`--integrated-arm64-as` option.

The new preflight performs two checks using vendor-like flags,
including `--prefix=/usr/bin/ -no-integrated-as -EL`:

1. Inspect `clang -###` and require ARM64 `cc1` with object emission
   and **no external assembler**.
2. Compile a tiny disposable C object in an automatically deleted
   temporary directory and validate the ELF magic, ELF64 class,
   little-endian encoding, and `EM_AARCH64` architecture identifier.

No stock kernel source, configuration, firmware, phone, or existing
output directory is changed during the dry-run probe.

First, pull the updated tool and run dry-run:

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
  --integrated-arm64-as \
  --verbose \
  --jobs 2
```

Expected `DRY RUN PASSED`; the report prints the Make command including
`KCFLAGS=--target=aarch64-linux-gnu -integrated-as` and a matching
`KAFLAGS`. The Clang probe is **not** a Samsung kernel Image build.

Only if that preflight passes, reuse the existing stock-only `O=`
directory with **fresh fifth-attempt logs**:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --verbose \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-05.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-05.json
```

If Make fails, capture:

```bash
grep -nE 'error:|fatal error:|Error [0-9]+|No such file|unrecognized option' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build-05.log | head -80
tail -n 85 ~/s20-artifacts/samsung-hxl1-image-clang18-build-05.log
```

The integrated assembler can expose **new incompatibilities** in
legacy Samsung assembly directives; the objective is a diagnostic,
off-device stock compatibility build. A successful `Image` remains
unsigned and nonflashable on the currently locked S20+.

## October 9: fifth Image build reaches ARM64 offsets; Clang 18 warning forbidden

The fifth owner-side Clang18/GCC13 build with
`--integrated-arm64-as --verbose` passed the external assembler blocker.
Samsung Kbuild completed `scripts/mod/empty.o`, `modpost` and the
host-side certificate-signing/extraction tools (OpenSSL 3 deprecations
were warnings, not fatal), generated `kernel/bounds.s` and
`include/generated/bounds.h`, then stopped while compiling
`arch/arm64/kernel/asm-offsets.s`:

```text
include/linux/cgroup-defs.h:475:16: warning:
field 'cgrp' with variable sized type 'struct cgroup' not at the
end of a struct or class is a GNU extension
[-Wgnu-variable-sized-type-not-at-end]
('error, forbidden warning:', 'cgroup-defs.h:475')
```

Samsung's `scripts/gcc-wrapper.py` treats **any emitted compiler
warning** as fatal. The recorded source is still stock and the warning
itself does not show a compiler crash or C syntax rejection. Modern
Clang 18 may diagnose GNU extensions that the original Qualcomm
Clang 10.0.6 did not warn about.

The sixth build option,
`--suppress-cgroup-layout-warning`, is intentionally narrow: it
adds *only* `-Wno-gnu-variable-sized-type-not-at-end` to
`KCFLAGS`, leaving `KAFLAGS`, compiler warning categories, Samsung's
wrapper, original source files and verified `.config` unchanged.

The guard requires `--integrated-arm64-as` and uses Clang's
`-fsyntax-only` on a tiny, embedded GNU flexible-layout example
to confirm that the named diagnostic first appears and then
disappears with this single opt-in suppression. This probe does
not compile kernel source or alter the existing build output.

Run the dry-run gate:

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
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --verbose \
  --jobs 2
```

If the dry run prints `DRY RUN PASSED` and the command's
`KCFLAGS` includes the single `-Wno-gnu-variable-sized-type-not-at-end`,
retry using **fresh** sixth-attempt log/report paths:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --verbose \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-06.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-06.json
```

If it fails, collect both ordinary compiler errors **and** Samsung's
nonstandard `error, forbidden warning` diagnostic:

```bash
grep -nE 'error:|forbidden warning|fatal error:|Error [0-9]+|No such file|unrecognized option' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build-06.log | head -100
tail -n 90 ~/s20-artifacts/samsung-hxl1-image-clang18-build-06.log
```

Any further warning or code-generation difference needs its own
investigation rather than broadly disabling warning checks or editing
Samsung's original source. Neither a compiled Image nor firmware
modification has yet occurred; the phone's bootloader remains locked.

## October 9: sixth Image build reaches VDSO, two exact upstream IAS fixes identified

The owner ran sixth stock-kernel `Image` compatibility test with
`--integrated-arm64-as --suppress-cgroup-layout-warning`, where the
Clang 18 cgroup layout diagnostic was successfully suppressed.
The build generated `include/generated/asm-offsets.h` and then failed
while preparing `arch/arm64/kernel/vdso`:

```text
arch/arm64/kernel/vdso/gettimeofday.S:230:24: error: too many positional arguments
arch/arm64/kernel/vdso/gettimeofday.S:253:24: error: too many positional arguments
arch/arm64/kernel/vdso/gettimeofday.S:274:24: error: too many positional arguments
arch/arm64/kernel/vdso/note.S:31:1: error: changed section flags for .note.Linux, expected: 0x2
```

Both match documented **upstream** Linux assembly fixes:

1. The Linux 4.19-stable patch
   [arm64: vdso: remove commas between macro name and arguments](https://www.spinics.net/lists/arm-kernel/msg893332.html)
   removes a comma from exactly three `clock_gettime_return, shift=1`
   calls, leaving the macro definition and other code untouched.
2. Linux commit
   [51da9dfb7f20911ae4e79e9b412a9c2d4c373d4b: elfnote mark all .note sections SHF_ALLOC](https://lists.openwall.net/linux-kernel/2020/03/25/1250)
   changes the assembly `ELFNOTE_START(name, type, "")`
   invocation in `include/linux/elfnote.h` to use `"a"`.
   This matches the mixed flags from a build-salt note in
   `note.S`.

**Do not apply either patch to the audited original Samsung tree.**
That would invalidate the original stock-source fingerprint and
could confuse experimental kernel output with firmware-identical
Samsung source.

### Create a separate, auditable experimental build-source copy

The repository's new `tools/prepare_samsung_vdso_compat.py` utility
implements the **two exact upstream changes only**, with strict
replacement counts (3 + 1) and no fuzzy patching. It uses
`shutil.copytree` (not hard links), keeping the source pristine.

An initial read-only preflight checks original Samsung kernel 4.19,
the original device defconfig hashes, and 40/40 overlay checksums.
After copying, the tool verifies that the complete copied tree
matches the original after accounting **only** for the two patched
file hashes. It writes a provenance manifest
`.samsung-vdso-compat.json` containing SHA-256 for both original
and changed files plus complete original/copied tree digests.

The copy may require substantial WSL filesystem space. Before
executing, inspect free space with `df -h ~/src`.

Dry-run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
df -h ~/src

python3 tools/prepare_samsung_vdso_compat.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json
```

If the dry-run finds the **exact four changes**, create the
experimental source-copy and its provenance manifest:

```bash
python3 tools/prepare_samsung_vdso_compat.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --execute
```

If the target exists, the command refuses to overwrite it.
It leaves `~/src/samsung-y2q-hxl1-stock` **unchanged** and does
not compile kernel Image, alter the phone, or write a bootloader
payload.

### Seventh off-device Image trial using source compatibility copy

The existing `tools/build_samsung_stock_kernel.py` now supports
`--compat-source-dir`. Its `--source-dir` remains the original,
40-overlay audited Samsung source. When a compat tree is selected,
it verifies both complete SHA-256 tree digests against the
provenance manifest before constructing the Make command against
the isolated compatibility tree.

Continue to use the **same** generated `.config` in the out-of-tree
`O=` directory, with its already verified SHA-256, **same**
Clang 18 + isolated Python 2.7, the integrated ARM64 assembler, and
the narrowly scoped cgroup warning suppression.

Dry-run:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --verbose \
  --jobs 2
```

When it prints `DRY RUN PASSED` and `Build source` shows
the *compatibility* copy, retry with fresh logs and report:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --verbose \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-07.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-07.json
```

If Make fails, extract the first errors (including those reported
by Samsung's warning-enforcing wrapper):

```bash
grep -nE 'error:|forbidden warning|fatal error:|Error [0-9]+|No such file|unrecognized option' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build-07.log | head -100
tail -n 90 ~/s20-artifacts/samsung-hxl1-image-clang18-build-07.log
```

**Integrity and safety:** This trial is **not strictly stock source**
because the experimental copy contains two documented upstream
compatibility patches. Build outputs are unsigned, cannot normally
boot on the owner's locked SM-G986U1, and must never be treated as
Samsung's release kernel. No device flash, signing, rooting or custom
kernel boot is involved.

## October 9: seventh Image build passes VDSO assembly, fails at native x86 linker

With the verified source-copy containing **only two upstream
compatibility patches**, the seventh experimental build passed
the previous assembler errors in `gettimeofday.S` and `note.S`.
It compiled these objects successfully:

- `arch/arm64/kernel/vdso/gettimeofday.o`
- `arch/arm64/kernel/vdso/note.o`
- `arch/arm64/kernel/vdso/sigreturn.o`

It then failed while linking `arch/arm64/kernel/vdso/vdso.so.dbg`:

```text
/usr/bin/ld: unrecognised emulation mode: aarch64linux
Supported emulations: elf_x86_64 elf32_x86_64 elf_i386 ...
clang: error: linker command failed with exit code 1
```

This is a **host linker selection problem**, not an assembler
issue: `/usr/bin/ld` is x86-64, whereas
`/usr/bin/aarch64-linux-gnu-ld` is installed for the ARM64 target.
Samsung's compiler invocation contains `--prefix=/usr/bin/`,
which selects the native linker by default.

### Eighth compatibility trial — explicit ARM64 GNU ld

The guarded build helper now accepts `--cross-arm64-linker`. Under
`--integrated-arm64-as` it adds to *C* flags only:

- `--ld-path=/usr/bin/aarch64-linux-gnu-ld` (select exact linker)
- `-Wno-unused-command-line-argument`

The second flag is needed because the very same Samsung
`$(c_flags)` reaches **both** normal C compilation and the VDSO
link command. Clang 18 diagnoses `--ld-path` as an unused argument
on `-c` commands; Samsung's `gcc-wrapper.py` rejects even that
warning. It is **not** a blanket warnings disable: the wrapper
remains intact; Clang 18's original source layout warning is still
the separately gated `-Wno-gnu-variable-sized-type-not-at-end`.

The new preflight:

1. Confirms the GNU AArch64 linker exists and is executable.
2. Inspects Clang's actual `-###` linker selection with Samsung
   `--prefix=/usr/bin/` and requires **the exact AArch64 ld path**,
   not host `/usr/bin/ld`.
3. Compiles and links a tiny disposable ARM64 shared object and
   validates ELF magic, little-endian class, `ET_DYN`, and
   `EM_AARCH64` in the output bytes.

No original Samsung files, the experimental source-copy, the
generated `.config`, or the phone are modified by this probe.

Pull branch and run the eighth dry-run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --cross-arm64-linker \
  --verbose \
  --jobs 2
```

Only if the dry-run passes, run the same complete build command
with `--execute` and **fresh** log/report filenames:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --cross-arm64-linker \
  --verbose \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-08.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-08.json
```

If it fails, extract **the earliest linker diagnostics** and
Samsung wrapper failures:

```bash
grep -nE 'error:|forbidden warning|fatal error:|Error [0-9]+|unrecognised|undefined reference|No such file' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build-08.log | head -100
tail -n 90 ~/s20-artifacts/samsung-hxl1-image-clang18-build-08.log
```

This is still an experimental, unsigned, off-device Image-only
test of Clang18/GCC13 against Samsung Linux 4.19.113, not a
flashable custom kernel for the locked SM-G986U1.

## October 9: eighth Image build passes VDSO linking and begins main ARM64 compilation

The eighth experimental Clang18/GCC13 build, using the isolated,
fully verified two-patch VDSO source, successfully linked
`arch/arm64/kernel/vdso/vdso.so.dbg` with
`/usr/bin/aarch64-linux-gnu-ld`, ran AArch64 `objcopy` to produce
`vdso.so`, and began building `init/main.o` plus ARM64 kernel objects.

Two **Clang warnings** stopped the build because Samsung's
`scripts/gcc-wrapper.py` rejects every compiler warning:

- `include/linux/seq_buf.h:35`: converting/assigning a
  `unsigned char *` to `char *`, warning `-Wpointer-sign`;
  affected `init/main.o` and `arch/arm64/kernel/process.o`.
- `arch/arm64/include/asm/sec_debug.h:113`: local
  `which_el` set but unused, warning `-Wunused-but-set-variable`,
  affected `arch/arm64/kernel/fpsimd.o`.

These are compatibility diagnostics in old Samsung source exposed
by Clang 18; no evidence yet that either reflects a code-generation
crash or security issue. They should still be tracked explicitly.

A separate `arch/arm64/kernel/entry.S` DWARF2 section warning was
observed but **did not cause the first reported failure**. Do not
disable assembly warnings globally.

### Ninth experiment: two independently validated Clang warning categories

The new opt-in `--suppress-legacy-core-warnings` requires all
prior successful compatibility options:

- `--integrated-arm64-as`
- `--suppress-cgroup-layout-warning`
- `--cross-arm64-linker`

It adds **exactly** `-Wno-pointer-sign` and
`-Wno-unused-but-set-variable` to `KCFLAGS`, not `KAFLAGS`.
The original Samsung source, two-patch compatibility source,
generated `.config`, and warning-enforcing wrapper remain intact.

Before allowing a Make invocation, the tool uses `clang -fsyntax-only`
on disposable built-in C snippets to verify each diagnostic is
emitted without its suppression and absent when its *specific*
suppression is applied. It additionally confirms an unrelated
`-Wunused-parameter` diagnostic remains enabled, preventing a
blanket warning-disable workaround.

**Caveat:** these two warning categories are disabled for the
experimental C compilation as a whole, not just the reported source
lines. This is for identifying further modern-toolchain
compatibility blockers; it does not establish binary equivalence
to the original Samsung kernel.

Pull and dry-run (retains previous output artifacts and existing
experimental source copy; no source preparation required):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --cross-arm64-linker \
  --suppress-legacy-core-warnings \
  --verbose \
  --jobs 2
```

If the dry run passes, start the ninth experimental `Image` attempt
with **new** filenames for the immutable log and report:

```bash
python3 tools/build_samsung_stock_kernel.py \
  --source-dir ~/src/samsung-y2q-hxl1-stock \
  --compat-source-dir ~/src/samsung-y2q-hxl1-vdso-ias-compat \
  --output-dir ~/src/samsung-y2q-hxl1-config-clang18 \
  --audit-json ~/s20-artifacts/samsung-hxl1-source-audit.json \
  --comparison-json ~/s20-artifacts/samsung-hxl1-generated-vs-device.json \
  --clang /usr/bin/clang \
  --gcc-prefix /usr/bin/aarch64-linux-gnu- \
  --python2 ~/opt/samsung-kernel-python2/bin/python2 \
  --integrated-arm64-as \
  --suppress-cgroup-layout-warning \
  --cross-arm64-linker \
  --suppress-legacy-core-warnings \
  --verbose \
  --jobs 2 \
  --execute \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-09.log \
  --json ~/s20-artifacts/samsung-hxl1-image-clang18-report-09.json
```

If it fails, extract both standard errors and Samsung's custom
strict-warning failure messages:

```bash
grep -nE 'error:|forbidden warning|fatal error:|Error [0-9]+|undefined reference|No such file' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build-09.log | head -100
tail -n 90 ~/s20-artifacts/samsung-hxl1-image-clang18-build-09.log
```

The device remains locked and untouched. A successful `Image`
would still be unsigned, untested on hardware, and unflashable on
the current locked bootloader.

## October 9: ninth attempt reaches ARM64 built-in archive, blocked by unclassified warning

The ninth Clang18 + two-patch compatibility-source Image attempt progressed
past both previously fatal warning categories
(`-Wpointer-sign` and `-Wunused-but-set-variable`) and reached
`arch/arm64/kernel/built-in.a`. The owner provided the output of a
keyword `grep` and `tail -n 90`. The **only fatal wrapper location** shown was:

```text
('error, forbidden warning:', 'main.c:720')
make[2]: *** [.../scripts/Makefile.build:338: init/main.o] Error 1
```

The **original Clang warning at init/main.c:720** was not included in the
supplied excerpt, because it occurs before the last 90 lines and the grep
searched for `error:`, not `warning:`. We must **not infer** a Clang
warning class or add another global `-Wno-...` flag yet.

### Read-only root cause extraction, no recompilation

Pull the branch, then run the new source-neutral diagnostic tool on
the **already existing ninth log**, which finds the compiler warning
by matching Samsung's fatal file:line marker to preceding Clang
warnings, even when `-j2` interleaves output:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/summarize_samsung_kernel_build.py \
  --log ~/s20-artifacts/samsung-hxl1-image-clang18-build-09.log
```

As a manual cross-check, read the earlier portion of the original full
build log (not the pasted tail extract):

```bash
sed -n '52,69p' ~/s20-artifacts/samsung-hxl1-image-clang18-build-09.log

grep -n -B 12 -A 3 'forbidden warning' \
  ~/s20-artifacts/samsung-hxl1-image-clang18-build-09.log | head -65
```

After seeing the exact Clang message and its `[-W...]` category,
evaluate whether the fix should be a source-level compatibility patch,
a compiler-version match, or a narrowly scoped opt-in flag. The long-term
preferred reference is Samsung's original **Clang 10.0.6** toolchain;
the current Clang 18 build is experimental and must not be assumed
equivalent.

For **future** failures, the builder also includes `failureSummary` in
its existing JSON build report, preserving the original verbose log.
That summarization doesn't override the Make return code and doesn't
alter the kernel build, source tree, or configuration.

**No tenth compilation has been started.** The original audited Samsung
kernel source and the generated `.config` remain unchanged. The source-copy
still contains only the two approved upstream VDSO compatibility patches.

## October 9: ninth-build `-Wformat` type mismatch classified — hold further build

The log summary reveals a specific Clang 18 warning at
`init/main.c:720:60`:

```text
warning: format specifies type 'unsigned long' but the argument has
type 'u64' (aka 'unsigned long long') [-Wformat]
('error, forbidden warning:', 'main.c:720')
```

This is a **format-specifier / vararg type mismatch**, not an
assembler or linker error. Disabling the broad `-Wformat` category
would hide real format bugs across the entire kernel. Do **not**
add `-Wno-format`, use `-w`, or modify Samsung's strict warning
wrapper.

The proper minimal correction will be in a *new* isolated, hashed
compatibility source variant **after inspecting the exact call**
around line 720. For a `u64` value, the familiar kernel pattern is
`%llu` with a corresponding `(unsigned long long)` cast, but
no specific source patch should be assumed before reviewing the
statement, its other format arguments, and macro expansion.

Read-only extraction from the owner's already extracted
compatibility and original stock trees:

```bash
nl -ba ~/src/samsung-y2q-hxl1-vdso-ias-compat/init/main.c |
  sed -n '711,728p'

nl -ba ~/src/samsung-y2q-hxl1-stock/init/main.c |
  sed -n '711,728p'

sha256sum \
  ~/src/samsung-y2q-hxl1-stock/init/main.c \
  ~/src/samsung-y2q-hxl1-vdso-ias-compat/init/main.c
```

These commands do **not** edit any files. Once the precise
printing call is known, implement only the required type-safe
format/argument correction in another audited source copy and
run the next guarded off-device Image test. Avoid adjusting
the user's already verified `.config`.

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
