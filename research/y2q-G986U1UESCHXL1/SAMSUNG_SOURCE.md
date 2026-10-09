# Matching Samsung Galaxy S20+ (SM-G986U1) HXL1 kernel source

## Exact source archive listed by Samsung

From the Samsung Open Source Release Center's North American Android 13
Galaxy S20+ release listing (models SM-G986U, SM-G986U1, SM-G986W),
the **Description** column includes:

`SM-G986U_13_Opensource_G986USQSCHXL1_G986U1UESCHXL1_G986WVLSCHXL1.zip`

**Target firmware:** `G986U1UESCHXL1`. The full filename explicitly includes
this firmware string, unlike the older revisions also present in the
release list. The top-level **Version** column is not the exact revision
of every cumulative source archive listed under **Description**.

Status:
- [x] Exact firmware token identified in Samsung source package listing
- [ ] Archive downloaded; size and SHA-256 recorded
- [ ] Outer and nested ZIP/TAR contents inspected
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

## Ubuntu in WSL2: inspect without unpacking

The Windows D: drive is mounted under `/mnt/d` in your existing WSL
environment. Open Ubuntu and run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

SOURCE_ZIP=$(find /mnt/d/root-my-galaxy-test/source \
    -maxdepth 1 -type f \
    -name '*G986U1UESCHXL1*.zip' -print -quit)

if [[ -z "$SOURCE_ZIP" ]]; then
  echo 'Could not locate the exact HXL1 source archive on D:' >&2
else
  printf 'Selected: %s\n' "$SOURCE_ZIP"
  python3 tools/inspect_samsung_source.py "$SOURCE_ZIP" \
    --json ~/s20-artifacts/samsung-source-inventory.json
fi
```

The inventory prints the ZIP's full SHA-256, size, outer members and
declared sizes, with a saved JSON report. This does **not** unpack the
multi-gigabyte archive or assert that any contained source builds correctly.
Do not treat arbitrary ZIP contents as trusted scripts or run them.

To inspect the headers of nested source TAR archives without
extracting them, optionally run:

```bash
python3 tools/inspect_samsung_source.py "$SOURCE_ZIP" \
    --scan-nested --max-tar-members 20000 \
    --json ~/s20-artifacts/samsung-source-detailed.json
```

Nested scans may take time because compressed data must be decompressed
sequentially. They stop at the member count limit; a truncated scan is
**not** evidence that files absent from the first 20,000 members do
not exist. The source inspector never executes or extracts archive data.

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
