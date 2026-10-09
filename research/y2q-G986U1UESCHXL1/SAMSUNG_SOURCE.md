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
- [ ] Inner base, U1 DTS, HXL1 ZIP and any nested TAR contents inspected
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
