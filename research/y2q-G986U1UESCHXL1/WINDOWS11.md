# Windows 11 / WSL2: Galaxy S20+ HXL1 research build workspace

This guide is specific to the Galaxy S20+ **SM-G986U1 (y2q)** running
**G986U1UESCHXL1** and kernel **4.19.113-27095354**. It prepares a
reproducible research build environment and compiles a harmless Android ARM64
**identity-check binary**. It is **not** an exploit, a KernelSU module, a
verified root method, or a flashable boot image.

## 1. Install Ubuntu under Windows 11

In **PowerShell as Administrator**:

```powershell
wsl --install -d Ubuntu-24.04
wsl --update
wsl --list --verbose
```

Restart when Windows asks. Open Ubuntu once and create its Linux user.
Ensure the distribution says `VERSION 2` in the final command.

In the **Ubuntu terminal**, install build and inspection prerequisites:

```bash
sudo apt update
sudo apt install -y git build-essential python3 python3-venv \
    clang llvm lld make cmake ninja-build unzip zip xz-utils \
    lz4 gzip file curl ca-certificates device-tree-compiler
mkdir -p ~/src ~/s20-artifacts ~/opt
cd ~/src
git clone --branch feature/s20plus-investigation-shizuku-20261009 \
    https://github.com/Ragnarok93/Root-My-Galaxy-Payloads.git
cd Root-My-Galaxy-Payloads
```

Keep the Git clone under the WSL/Linux filesystem (`~/src`) for build
performance; use `/mnt/c` to access files in Windows Downloads.

## 2. Verify firmware provenance (no changes to the phone)

Copy your previously extracted component files into `~/s20-artifacts`,
renaming **copies**, not the original files. Replace `<WinUser>` below with
your Windows sign-in folder name:

```bash
WIN=/mnt/c/Users/<WinUser>/Downloads
cp "$WIN/boot.img.lz4" ~/s20-artifacts/boot.img.lz4
cp "$WIN/S20plus-G986U1UESCHXL1-boot.img" ~/s20-artifacts/boot.img
cp "$WIN/S20plus-G986U1UESCHXL1-kernel.bin" ~/s20-artifacts/kernel.bin
cp "$WIN/S20plus-kernel-config.gz" ~/s20-artifacts/config.gz

python3 tools/verify_s20plus_firmware.py --files ~/s20-artifacts
```

The tool checks **size and SHA-256** against
`research/y2q-G986U1UESCHXL1/evidence.json`. Missing optional input files
are skipped; the tool fails if no inputs are available, or if any supplied
file differs. A passing hash verifies the **file you have**, not a direct
measurement of the handset's protected boot partition.

For convenience, check the original compressed boot image alone:

```bash
sha256sum ~/s20-artifacts/boot.img.lz4
# Expected: 02099ccbfb423292b631f228b8d3163b9a601f4a058360a4bca93f71f8e50a78
```

## 3. Install the Linux Android NDK and compile a real ARM64 program

This part uses the **Linux NDK inside WSL**, not the Windows NDK binaries.
Google publishes NDK r30 for Linux; it is a recent toolchain for building
Android userspace diagnostics (not a substitute for the original Samsung
Clang 10 toolchain that built this kernel).

```bash
cd ~/opt
curl -fL --retry 3 -o android-ndk-r30-linux.zip \
    https://dl.google.com/android/repository/android-ndk-r30-linux.zip
unzip -q android-ndk-r30-linux.zip
export ANDROID_NDK_HOME="$HOME/opt/android-ndk-r30"
cd ~/src/Root-My-Galaxy-Payloads
bash research/y2q-G986U1UESCHXL1/build_probe.sh
```

Output:
`research/y2q-G986U1UESCHXL1/build/y2q-identity-probe`.

It is an **ELF executable for Android 13 / arm64-v8a**, not a `.so`
preload or a kernel `.ko` module. It reads only public Android build
properties and `uname`, displays UID and page size, and exits with:

- `0` when the selected exact device/build/kernel identifiers match.
- `2` on a firmware identity mismatch.
- `3` if `uname` fails.

It never attempts privilege escalation, module loading, kernel memory
access, flashing or modifications.

## 4. Run the identity checker on the phone

Install Google's **Android SDK Platform-Tools** on Windows if needed.
Connect the phone using USB debugging, or establish an authorized wireless
ADB session. In Windows **PowerShell**:

```powershell
adb devices
```

Copy the ELF from Ubuntu into Windows Downloads (from the Ubuntu terminal):

```bash
cp ~/src/Root-My-Galaxy-Payloads/research/y2q-G986U1UESCHXL1/build/y2q-identity-probe \
   /mnt/c/Users/<WinUser>/Downloads/y2q-identity-probe
```

Then in Windows PowerShell:

```powershell
adb push "$env:USERPROFILE\Downloads\y2q-identity-probe" /data/local/tmp/y2q-identity-probe
adb shell chmod 755 /data/local/tmp/y2q-identity-probe
adb shell /data/local/tmp/y2q-identity-probe
```

Expected tail: `RESULT=FIRMWARE_IDENTITY_MATCH` and a notice that identity
checking is not a root test. The tool runs with ordinary ADB-shell privileges
(typically UID 2000). You do **not** need to enable root.

## 5. Locate and assess the matching Samsung source

Use the **Samsung Open Source Release Center** at
https://opensource.samsung.com/ and search for
`SM-G986U1` (and alternatively the shared North American Snapdragon
Galaxy S20 kernel source packages). Record the package's **model, version,
release date, download name, and SHA-256**. Do not assume a similar regional
model source is exact or that a publicly available source package contains
Samsung's proprietary RKP/KDP implementation.

Check the source package's actual build instructions and defconfig against
the supplied `config.gz`. The original kernel reports **Clang 10.0.6**;
building with modern NDK r30 Clang may produce a different binary even when
source and config are logically compatible.

A source archive and a successful kernel build would establish a **build
baseline**, not the ability to boot unsigned images or load arbitrary
modules on a locked production handset.

## 6. Research release gates

Do not treat the existing `make TARGET=...` targets as templates for this
phone: they contain **other devices' kernel-specific assumptions**. The app
support catalog currently matches `SM-G986U1` plus the short kernel version
too broadly to safely distinguish firmware revisions.

The collected device data shows **locked bootloader / AVB**, enforcing
SELinux, mandatory kernel-module signatures, Samsung RKP/KDP/DEFEX and no
unprivileged access to `/proc/kallsyms`. KernelSU's official non-GKI
integration instructions are **archival**, and do not establish a ready-to-use
4.19 loadable module for this firmware. The absence of an OEM unlock option
cannot be resolved by compilation alone.

Only mark a rooting integration as working after the relevant source
matches, the security boundary and compatibility are independently reviewed,
a legitimate installation/recovery path is established, and device tests
demonstrate stable operation. **No such payload is available in this research
directory.** Do not flash experimental images to this locked device.

Official documentation:
- https://learn.microsoft.com/en-us/windows/wsl/install
- https://developer.android.com/ndk/downloads
- https://developer.android.com/tools/releases/platform-tools
- https://opensource.samsung.com/
- https://kernelsu.org/guide/how-to-integrate-for-non-gki.html
