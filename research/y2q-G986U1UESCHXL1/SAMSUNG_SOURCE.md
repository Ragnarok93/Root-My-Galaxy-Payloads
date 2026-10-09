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
