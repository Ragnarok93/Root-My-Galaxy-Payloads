# Stage 4: extract the actual original HXL1 Qualcomm LinuxLoader

**Status: original HXL1 PE extraction not yet run; physical Linux load unknown.**

The owner verified original SHA256 and scanned the entire original abl.elf, xbl.elf and xbl_config.elf for standard FDT magic. All three gave ZERO. More FDT-signature searches will not recover the loader's physical handoff.

**New path:** Qualcomm's official https://github.com/qualcomm/abl2esp documents an ELF32-wrapped ABL containing outer UEFI FV, GUID-defined LZMA, nested FV and a LinuxLoader PE32+ app. Its package.sh explicitly uses 0x9fa00000, matching the original HXL1 ABL ELF entry value. This supports the ABL packaging-family hypothesis, not equality of binary code. https://github.com/linux-msm/xbltools confirms LinuxLoader handles Android boot images.

New tools:
- tools/y2q_abl_linuxloader_extract.py: SHA256/size-pin original 4,194,304-byte HXL1 ABL, decode nested standard FVs, FFS, GUID LZMA, PE32+; select one LinuxLoader AArch64 PE with provenance and its own SHA256; refuse missing/ambiguous result and refuse writing to the original input.
- tools/test_y2q_abl_linuxloader_extract.py: six synthetic tests passed locally, including full nested-FV/LZMA/PE recovery. This does NOT prove real Samsung ABL extraction until owner executes it.
- The extracted PE and JSON report remain local: ~/s20-artifacts/hxl1-research/abl-linuxloader.

Owner commands:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools/test_y2q_abl_linuxloader_extract.py
    python3 tools/y2q_abl_linuxloader_extract.py

If it succeeds, do NOT confuse the PE's preferred image base or entry RVA with Linux physical load. Next analyze the *actual* recovered PE program:

    OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
    file "$OUT/LinuxLoader-HXL1.efi"
    sha256sum "$OUT/LinuxLoader-HXL1.efi"
    llvm-readobj --file-headers --sections "$OUT/LinuxLoader-HXL1.efi" > "$OUT/linuxloader-pe-headers.txt"
    llvm-objdump --disassemble "$OUT/LinuxLoader-HXL1.efi" > "$OUT/linuxloader-disassembly.txt"
    { strings -a -n 5 "$OUT/LinuxLoader-HXL1.efi"; strings -a -e l -n 5 "$OUT/LinuxLoader-HXL1.efi"; } |
      grep -Ei 'kernel|load|boot|dtb|fdt|handoff|ramdisk|memory' |
      sort -u > "$OUT/linuxloader-interesting-strings.txt"
    cat "$OUT/linuxloader-interesting-strings.txt"

Trace the loader's Android boot-v2 parsing, kernel Image header text_offset and image_size handling, memory/DRAM base determination, chosen DTB and ultimate AArch64 branch/jump to the calculated kernel entry. Corroborate with the pinned original kernel image and Kona v2.1 DTB. **Only verified dataflow to the loader's jump can support a candidate physical handoff.**

If the native unpacker fails, use the mature independent https://github.com/theopolis/uefi-firmware-parser command uefi-firmware-parser -b -e on the hash-pinned ABL, and report the missing nested structure/compression format. Never invent results from generic signature scans.

Gate state: Stage 3 ABI PARTIAL; Stage 4 load/handoff OPEN; runtime exploit and KernelSU BLOCKED; no device modifications or support publication.

## 2026-10-10 — first original ABL extraction failure and repair

Owner pulled commit `a9ebb7e` and ran 6/6 synthetic tests successfully, but running the extractor on the exact original HXL1 `abl.elf` stopped with `[STOP] Firmware container object limit exceeded`. No `LinuxLoader-HXL1.efi` was produced; subsequent `llvm-readobj`/disassembly commands failed because the binary/output folder did not exist. **This is a host parser failure, NOT evidence the original ABL lacks LinuxLoader.**

Root cause identified in parser control flow: its firmware-volume walker used to increment the count and then advance by 8 bytes over every 24-byte run of erased `0xFF` or `0x00`. A large erased padding tail can therefore consume more than 5,000 'objects' without finding anything. The real original ABL is 4 MiB, so this is a credible explanation of the observed stop, not yet a measurement of its actual FV layout.

Repair commits beginning `b92289e`:
- End FFS parsing when the trailing volume region is erased/blank instead of scanning it as many fake objects.
- End a malformed FFS sequence with an explicit note instead of blindly skipping offsets.
- Preserve a **structured host-only diagnostic file** `~/s20-artifacts/hxl1-research/abl-linuxloader/linuxloader-extraction-diagnostics.json` when extraction fails, including accepted volume traces, candidate PE metadata, object counts and parse notes.
- Added a synthetic 1 MiB erased-FV regression and a fail-closed no-loader diagnostic regression, bringing the tests to **8 expected**, to be verified against the owner's WSL2 checkout; synthetic tests do not establish original ABL extraction.

Do not attempt PE disassembly unless `LinuxLoader-HXL1.efi` exists and has passed the PE verification. If the repaired parser fails, use its exact diagnostic layers to refine real input format handling, rather than repeat FDT/strings surveys.

## Original HXL1 ABL inner FV is now independently decoded — 2026-10-10

The owner ran commit `4636439`: all **8 previous synthetic tests passed** and the real original ABL hash matched. The repaired parser **successfully traversed both firmware volumes and decompressed the GUID-LZMA section**:

- Original ABL SHA256: `6d717ef96e7355d72db1ac167ef1b74ff6ef33d22a8bfc08affc62f9cabcdeef`, size **4,194,304**.
- Outer FV at original ABL file offset `0x3000`, `0x220000` bytes.
- Outer FFS GUID `9e21fd93-9c72-4c15-8c4b-e77f1db2d792`, type `0x0b`; GUID-defined LZMA section `ee4e5898-3914-4259-9d6e-dc7bd79403cf`.
- LZMA decoded section: **6,889,864** bytes. Its volume-image section `0x17` contains an inner FV at nested offset `0x0`, with length `0x692180` (**6,889,856** bytes).
- Traversal finished after 20 objects, no runaway erased-space loop, and two accepted firmware volumes. **Zero AArch64 PE candidates** passed our custom `identify_pe` validator. This is a remaining **internal FFS / executable section interpretation gap**, not a missing LZMA layer.
- The zero-PE diagnostic did not record the individual inner FFS names, sizes or section types, so it cannot yet determine if a valid PE was rejected, nested differently, or represented as a TE image. No loader output was generated.

**Targeted repair:** the native parser now retains per-FFS and per-section provenance, UI names, section header prefixes and hash, rejected PE32 and TE signatures, and supports EFI no-compression wrapping. All errors preserve a JSON diagnostic; the tool still refuses to fabricate a loader. Added 2 synthetic tests, so the revised suite has **10 tests** (awaiting owner run).

**Independent production-quality fallback:** `tools/recover_y2q_hxl1_linuxloader.sh` pins/checks the original ABL hash, runs the native extractor, and if needed installs PyPI `uefi-firmware==1.16` into a private host venv. It uses upstream `uefi-firmware-parser -b -e` to extract nested Qualcomm FVs independently. It promotes a file to `LinuxLoader-HXL1.efi` **only if** it is an AArch64 PE32+ section within the decoded FFS folder matching the exact LinuxLoader GUID. Ambiguous or absent outputs remain unverified with JSON diagnostics; no other .efi is guessed.

**Next exact command (single recovery pass):**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/recover_y2q_hxl1_linuxloader.sh
```

If the native decoder fails, the tool reports all verified inner files and sections before running the independent decoder, so even a failure yields targeted evidence rather than another FDT or strings survey. Results stay local under `~/s20-artifacts/hxl1-research/abl-linuxloader/` and no bootloader code is executed.

Physical Linux kernel handoff, actual DTB selection, factory ABI and live exploitability all remain UNVERIFIED.


## October 10 — real stock LinuxLoader file identified; REA fork integration

Owner executed the recovery wrapper through commit `2ac62f2`; all **10 local synthetic regression tests** passed. **Both** original ABL format decoders independently identified the full, decoded nested EFI firmware filesystem. The mature `uefi-firmware==1.16` reported:

- Outer FV `0x3000` / `0x220000`; inner FV `0x692180` after LZMA.
- Inner applications: `Odin` (FFS `aba3b456-5469-414a-9f79-47cecbd7c04e`), **`LinuxLoader`** (FFS `f536d559-459f-48fa-8bbc-43b554ecae8d`), `Cryptest`, and `QuestSOD`.
- LinuxLoader UI section `0x15` reads `LinuxLoader`; executable section `0x10`, 3,575,808 bytes **of section payload**, beginning `MZ`.
- Independently dumped exactly this file in `independent-unpacked/.../file-f536d559-459f-48fa-8bbc-43b554ecae8d/section1.pe`. The stock ABL SHA256 was independently checked again.
- **Actual cause of the independent recovery selector's zero candidates:** it only searched `.pe32` / `.efi` filenames, not the `.pe` suffix used by the independent decoder. This is a tool bug, not absence of the stock LinuxLoader.
- **Separate issue still unresolved:** custom `identify_pe` rejected all four `MZ` PE-section payloads. The reason (COFF architecture, DOS e_lfanew, optional-header variant or validator constraint) is NOT established from the first-64-byte diagnostic. Do not silently call the recovered bytes a verified AArch64 PE32+ image.

### Fixed recovery: exact GUID + UI + actual .pe suffix

`tools/recover_y2q_hxl1_linuxloader.sh` now accepts `.pe` and requires both exact FFS GUID and sibling UTF-16 UI `LinuxLoader`. It reports the actual DOS `e_lfanew`, optional-header magic, COFF machine and section count before accepting the strict checker. If the full native AArch64-PE validator still rejects the bytes, it **preserves them as `LinuxLoader-HXL1.unclassified.pe`**, with original SHA256/FFS/UI evidence and explicitly unverified architecture, so independent LLVM and decompiler inspection can proceed. It does not fake a successful validated-PE outcome.

### Direct use of our REA fork (not a generic npm version)

The owner has `Ragnarok93/rea`: https://github.com/Ragnarok93/rea, `main` reviewed at commit `46c9cba03a52b8ec382a686cd70ded6128225db8`. Its own reverse-engineer-anything SKILL.md specifies that actual native shipped binaries go to the **Ghidra/Hopper/IDA native provider**; its firmware-analysis workflow uses separately supplied Binwalk/Unblob, which would repeat already completed ABL extraction and is *not the next useful tool*. Its native Ghidra provider enables function overview, pseudocode, cross-references and value-flow evidence for investigating image placement and boot handoff, subject to the actual PE import and Ghidra availability. The skill does **not** register a working MCP server or install Ghidra by itself.

`tools/analyze_y2q_hxl1_linuxloader_rea.sh`:
1. Fails closed unless the **original stock ABL hash** and recovered loader digest/provenance match;
2. collects actual `file`, `llvm-readobj`, and `llvm-objdump` header/assembly reports;
3. calls the **user's fork** `~/src/rea/scripts/rea.mjs`, after checking its Node 22.19+, 24.11+, or 26+ requirement, for a Ghidra provider overview and focused loader searches;
4. does NOT clone/install a toolchain or Ghidra silently, change agent settings, execute the firmware PE, read the device, or assert kernel physical loading.

**Commands after this commit:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/recover_y2q_hxl1_linuxloader.sh || true
bash tools/analyze_y2q_hxl1_linuxloader_rea.sh
cat ~/s20-artifacts/hxl1-research/abl-linuxloader/linuxloader-file-classification.txt
cat ~/s20-artifacts/hxl1-research/abl-linuxloader/independent-uefi-recovery.json
```

The `|| true` does **not** mark a failed extractor as a success: the second command authenticates an actually recovered file against evidence and refuses missing/mismatched outputs. We run it because the current strict validator's unresolved PE variant may still cause the initial wrapper to return 2 **after** preserving authentic GUID/UI-bound bytes.

For deeper actual handoff work, once Ghidra admission is demonstrated, follow relevant `LinuxLoader` PE functions from Android boot-v2 header handling to `Image.text_offset`, memory allocation/placement and final AArch64 indirect jump. Record concrete disassembly and value-flow references and cite them separately from assumptions. Neither successful Ghidra import nor decompilation alone yields a physical kernel address.


### Next operator action: no re-extraction, use REA fork directly

A more efficient later change introduced `tools/y2q_hxl1_cached_linuxloader.py`. Its only inputs are the **existing** native `linuxloader-extraction-diagnostics.json`, existing independent `independent-unpacked/.../file-f536d559-459f-48fa-8bbc-43b554ecae8d/section1.pe` and adjacent `section0.ui`, and the original pinned ABL. It asserts that:
- The original ABL hash and size still match HXL1.
- The native decoder recorded **one** `LinuxLoader` FFS application and one `0x10` executable section.
- The independent decoder's FFS GUID and UTF-16 UI both identify `LinuxLoader`.
- The independent section's **entire SHA256, length and first 64 bytes** equal the native decoder's record of that original section.

It writes `LinuxLoader-HXL1.unclassified.pe` and `linuxloader-cached-correlation.json`, including measured DOS/COFF header fields and **without promoting unclassified architecture to AArch64 PE32+**. SHA or identity mismatches fail closed. 9 offline synthetic fixture tests were added; actual HXL1 run remains pending.

`tools/analyze_y2q_hxl1_linuxloader_rea.sh` now runs that cached correlation automatically when there is no previously verified `LinuxLoader-HXL1.efi`; it then collects `file` and LLVM PE/assembly reports, and when the owner's `~/src/rea` fork and native Ghidra provider are already functional it executes `node ~/src/rea/scripts/rea.mjs analyze ... --provider ghidra --json` and focused `search` commands. The REA tool registration, provider availability and Ghidra import are **not yet demonstrated on the owner's WSL2 environment**.

**Single new command for next operator test:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/analyze_y2q_hxl1_linuxloader_rea.sh
```

Do **not** re-run the whole decompression/UEFI extraction chain: the original PE section is already saved and independently fingerprinted. If REA's fork/Node/Ghidra is absent, the command preserves the raw original loader classification and reports precisely which dependency is missing without installing an arbitrary tool or claiming success.


## 2026-10-10 — original LinuxLoader section confirmed; wrong 0x800 DOS stub cap fixed

The owner's next WSL2 run (using commit `7b5520f`) verified all **nine synthetic cached-correlation tests** and passed the **real dual-decoder cached byte comparison** against exact firmware G986U1UESCHXL1. Verified original LinuxLoader:

- Exact FFS GUID `f536d559-459f-48fa-8bbc-43b554ecae8d`, UTF-16 UI `LinuxLoader`.
- EFI PE section body **3,575,808 bytes**.
- SHA256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`.
- DOS PE header pointer `e_lfanew=0xe58`; signature `PE\\0\\0`; COFF machine `0xaa64` (AArch64); optional-header magic `0x20b` (PE32+); COFF optional size `0xf0`; **3 sections**.
- Host `file` independently classified this SHA-pinned binary as **PE32+ executable (EFI application) Aarch64**.
- The custom `identify_pe` incorrectly imposed an arbitrary `e_lfanew <= 0x800` limit, rejecting the valid original offset `0xe58`. This was the final PE parser defect, NOT an unsupported Qualcomm format.

**Repair:** `tools/y2q_abl_linuxloader_extract.py::identify_pe` now accepts header locations within the actual file bounds, while requiring a complete COFF header, complete optional header, a complete section table, AArch64 machine and PE32+ magic. Synthetic test coverage now includes original-format `0xe58`, valid 3-section image, out-of-file header and truncated section table. `tools/y2q_hxl1_cached_linuxloader.py` upgrades the previously authenticated existing section to `LinuxLoader-HXL1.efi` if and only if the **original ABL, both decoders' SHA256/size/FFS/UI comparison, and strict PE32+/AArch64 parser** pass. It retains the original `LinuxLoader-HXL1.unclassified.pe` for audit continuity and never reruns LZMA/UEFI unpacking. `tools/analyze_y2q_hxl1_linuxloader_rea.sh` then authenticates that promoted ELF **PE** against the cached verified provenance.

**REA fork availability:** Owner's most recent WSL2 analysis halted after successfully preserving `file`, `llvm-readobj` and `llvm-objdump` reports because `~/src/rea` **does not exist**. The task-specific native REA/Ghidra analysis is therefore **not yet run**. The connected repo `Ragnarok93/rea`'s reverse-engineer-anything skill explicitly distinguishes native artifact evidence from source inspection. Running the skill does NOT install the REA CLI, Node, or Ghidra.

Next owner commands, no firmware re-unpacking:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools/test_y2q_abl_linuxloader_extract.py tools/test_y2q_hxl1_cached_linuxloader.py
python3 tools/y2q_hxl1_cached_linuxloader.py

# One-time REA fork setup in WSL2 if Node 22.19+, 24.11+, or 26+ is installed.
node --version
npm --version
git clone https://github.com/Ragnarok93/rea.git ~/src/rea
cd ~/src/rea
npm ci
npm run build
node scripts/rea.mjs providers --json
node scripts/rea.mjs doctor --provider ghidra --json

# From Root repo; only runs Ghidra if already available and compatible.
cd ~/src/Root-My-Galaxy-Payloads
bash tools/analyze_y2q_hxl1_linuxloader_rea.sh
```

If `doctor --provider ghidra` reports missing Ghidra, install/configure a supported Ghidra from an official distribution, then re-run the REA command. Do not substitute a different provider silently, and do not claim any decompilation or AArch64 handoff result before analyzing the recovered genuine PE.

**Stage 4 remains OPEN**: identifying the original LinuxLoader executable and its PE file format does not prove physical Linux load/entry, DTB selection, runtime vulnerability reachability or KernelSU.


## 2026-10-10 WSL2 confirmation: real LinuxLoader now recovered and *validated*

The owner ran both previous regression suites against commit `62ef218`: **24/24 PASS**, and the real SHA-pinned original HXL1 LinuxLoader passed dual-independent-FV-decoder integrity, FFS GUID/UI, and AArch64 PE32+ validation:

```text
[VERIFIED EFI] /home/main/s20-artifacts/hxl1-research/abl-linuxloader/LinuxLoader-HXL1.efi
coffMachine=0xaa64; optionalHeaderMagic=0x20b; e_lfanew=0xe58
coffSectionCount=3; coffOptionalHeaderSize=240
entryPointRva=0x1000; preferredImageBase=0x0
fileBytes=3575808; sizeOfImage=3575808
sha256=5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003
```

Note: synthetic fixture under `/tmp/tmppid3o0kv/` had `entryPointRva=0x120` and image base `0x100000`. **These are fixture values; NEVER use them for real HXL1.** The *real* EFI's PE entry-point RVA `0x1000` is an EFI application program entry, **not** the Linux kernel's physical entry address.

### Remaining host-only REA toolchain failure (do not re-extract firmware)

Owner's REA checkout exists at `~/src/rea`, but original WSL2 `node --version` prints **v18.19.1** while `npm --version` prints **11.19.0** from the **Windows npm executable**. During `npm ci`, that Windows npm invoked `C:\\WINDOWS\\system32\\cmd.exe` and Windows Node `v24.21.0` using a `\\\\wsl.localhost\\Ubuntu-24.04\\...` UNC current-directory path, leading to `Cannot find module 'C:\\Windows\\install.js'`, ESBuild postinstall failure and absent package build. Direct `node scripts/rea.mjs doctor` used the old Linux Node 18 and failed importing `package.json` due to JSON import attribute support.

**This is a mismatched host toolchain, NOT a PE or Ghidra failure.** Neither the REA checkout nor 3.6 MB verified loader needs cloning or re-extraction.

The new opt-in `tools/bootstrap_y2q_rea_wsl.sh`:
1. Requires the **existing REA checkout** (no duplicate git clone, no reset/rebase);
2. on Linux, clones the **tag-pinned nvm v0.40.3** only if missing, activates native Linux **Node 24.11+** via `nvm install 24` and `nvm alias default 24`;
3. verifies **both** `node` and `npm` resolve under `~/.nvm/versions/node/...` before running any npm install scripts;
4. rebuilds the **existing REA fork** using `npm ci --no-audit --no-fund` (replaces broken Windows-produced `node_modules`) and `npm run build`;
5. saves REA `providers` and `doctor --provider ghidra` reports under the local HXL1 loader research folder. A missing Ghidra is an explicit **next prerequisite**, never treated as proof of a loader problem.

The companion `tools/analyze_y2q_hxl1_linuxloader_rea.sh` now loads native nvm Node when running noninteractively so the same original WSL2 Windows npm/Node issue cannot silently return.

**Next command (already has original loader, no unpacking):**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/bootstrap_y2q_rea_wsl.sh
bash tools/analyze_y2q_hxl1_linuxloader_rea.sh
```

If REA's Ghidra doctor reports unmet prerequisites, REA's docs require an **existing official Ghidra 12.1.x** and compatible **64-bit full JDK 21+**, with `GHIDRA_INSTALL_DIR` and, if needed, `JAVA_HOME` set to actual Linux installation paths. No REA installer downloads Ghidra. REA's native Ghidra provider can then follow the original Android boot image parsing and kernel placement control flow. Stage 4 stays **OPEN** until original-loader code/dataflow actually proves a physical kernel load/handoff.


## 2026-10-10 WSL2: REA toolchain repaired; Ghidra remains the sole provider blocker

Owner ran `tools/bootstrap_y2q_rea_wsl.sh` from commit `5ac9416`. Results:

- Pinned `nvm` installed native Linux Node **v24.21.0** and Linux npm **v11.19.0** under `/home/main/.nvm/versions/node/v24.21.0/bin/`; no more WSL UNC path / Windows npm.
- Existing `Ragnarok93/rea` checkout remains at commit `46c9cba03a52b8ec382a686cd70ded6128225db8`, **REA 6.3.0**.
- `npm ci` successfully installed 376 packages; `npm run build` completed 3/3 compilation/metadata/skill tasks. A warning about esbuild postinstall approval was nonfatal and did not block REA's TypeScript build.
- The REA provider doctor reported **Ghidra not ready**. Report is on the owner's host at `~/s20-artifacts/hxl1-research/abl-linuxloader/rea-ghidra-doctor.json`; the exact doctor field values were **not yet pasted** and must not be invented. The REA analysis wrapper attempted native Ghidra and failed before importing PE, with diagnostics saved at `rea-ghidra-errors.txt`.
- The original verified LinuxLoader remains exact, with SHA256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`. No LZMA unpack, kernel/physical address or device action is needed.

**Provisioning strategy:** `tools/setup_y2q_rea_ghidra_wsl.sh` diagnoses existing installations by default. The explicit opt-in `--install` checks for a full Linux JDK 21+ and installs Ubuntu `openjdk-21-jdk` if absent (may prompt for sudo); obtains official **NationalSecurityAgency/ghidra Ghidra 12.1.4** 2026-09-21 release from GitHub, and independently validates SHA256 **`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`** before extraction. Its expected original asset filename is `ghidra_12.1.4_PUBLIC_20260921.zip`; the official release archive is about 570 MB. The verified software lands under `~/opt/ghidra_12.1.4_PUBLIC`, not the root filesystem. The script saves local `GHIDRA_INSTALL_DIR`/JDK environment to `rea-ghidra-env.sh`, runs the **fork's real** `doctor --provider ghidra` and retains JSON+stderr. `tools/analyze_y2q_hxl1_linuxloader_rea.sh` sources that scoped environment before the Ghidra analysis. No agent/MCP registration or Ghidra provider success is assumed.

**One actionable WSL2 command pair:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/setup_y2q_rea_ghidra_wsl.sh --install
bash tools/analyze_y2q_hxl1_linuxloader_rea.sh
```

The first command will download a substantial official archive and may need `sudo` for Java; users preferring to check an existing installation first can omit `--install`. Failures retain direct doctor diagnostics rather than repeating firmware signatures or PE extraction.

**Next *technical* target after successful REA/Ghidra provider import:** use recovered AArch64 loader PE decompilation, cross-refs and p-code value flow to reconstruct actual Linux Image allocation, DTB selection and final indirect control transfer. Stage 4 remains OPEN until the executable's dataflow supplies independently corroborated physical handoff evidence; no root or KernelSU is yet demonstrated.


## 2026-10-10: Ghidra 12.1.4 verified installed, but missing Unix execute permissions are likely

Owner ran the Ghidra provisioning utility through commit `29e67f6`. The full `openjdk-21-jdk` suite installed on Ubuntu 24.04; the official 2026-09-21 NSA Ghidra 12.1.4 archive downloaded in full (**543 MiB**) and passed SHA256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`; the archive was successfully extracted to `/home/main/opt/ghidra_12.1.4_PUBLIC`. The script exported `GHIDRA_INSTALL_DIR` and `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`, and the original independently SHA-pinned LinuxLoader remained intact. REA's doctor still reported **provider not ready**. The log did not include the *new* doctor JSON fields from after installation, so no specific failed check should be falsely attributed to the report.

**Concrete installer bug:** it used Python `zipfile.ZipFile.extractall()`, which does **not preserve Unix executable permissions** in the extracted files. REA fork `src/ghidra/GhidraInstallation.ts` explicitly requires `host.executable(support/analyzeHeadless)` and a compatible executable `Ghidra/Features/Decompiler/os/linux_x86_64/decompile`, making missing executable bits the leading hypothesis. `support/launch.sh` must also be executable for Ghidra's launcher. The failing doctor must be rerun after repair to establish whether this is the only issue.

**Targeted repair:** `tools/y2q_repair_ghidra_executable_modes.py` reads the **already-downloaded** official ZIP, rejects an incorrect SHA256, and checks byte-for-byte identity of every selected installed executable against its pinned original ZIP member. It restores archived execute permissions as appropriate plus those for three specific required Ghidra scripts/native tools; all targeted file verification completes before any chmod operations. It never touches Samsung firmware, REA binaries, Java or user projects. Seven offline fixture tests cover idempotence, no modification on dry run, tamper rejection and symlink refusal.

`tools/setup_y2q_rea_ghidra_wsl.sh` now invokes the repair automatically for this exact existing Ghidra archive/installation (including in **diagnose** mode), then runs REA's real Ghidra doctor. On failure it prints the exact failed `ghidra` provider checks rather than only a file path.

**Use this command next, without --install**; do not redownload or re-extract anything:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/setup_y2q_rea_ghidra_wsl.sh
bash tools/analyze_y2q_hxl1_linuxloader_rea.sh
```

The Ghidra installer needs no device access and the static LinuxLoader analysis remains separate from proving any kernel physical handoff. Stage 4 stays OPEN.

## October 10 — REA/Ghidra provider operational on actual HXL1 LinuxLoader

The owner ran SHA256-pinned Ghidra permission restoration and native REA analysis on WSL2. Results:

- **7/7** ZIP-mode regression tests passed.
- The official NSA 12.1.4 release ZIP and **all 134 selected installed executable files** passed byte-level verification against the original archive before `chmod`; executable modes were restored on **134/134** files.
- The **actual REA 6.3.0 Ghidra doctor passed**, using Ghidra 12.1.4 and full Ubuntu OpenJDK 21, under Node 24.21.0.
- The already-recovered LinuxLoader remained SHA256 **`5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`**.
- `tools/analyze_y2q_hxl1_linuxloader_rea.sh` completed successfully and saved REA's `binary_overview` plus three `search_strings` queries (`bootimg`, `kernel`, `dtb`) and raw LLVM output in the local HXL1 research folder.
- **Important limit:** successful overview/search proves Ghidra provider admission and static search execution, NOT that the kernel placement function, chosen DTB, or physical Linux handoff was recovered. The actual REA JSON search matches were not included in the user's terminal output and must not be invented.

### Next evidence gate: already-saved REA strings, then selected xrefs/decompilation

The new offline `tools/y2q_linuxloader_rea_stage4_seeds.py` verifies the original LinuxLoader SHA256, then reads existing `rea-ghidra-search-bootimg.json`, `rea-ghidra-search-kernel.json`, and `rea-ghidra-search-dtb.json`. For each, it requires a REA `search_strings` Evidence record whose provider is `ghidra`, whose target digest and architecture match the exact recovered PE and AArch64, and whose actual query matches the filename. It reports every Ghidra analyzed string address and value, retains evidence IDs, and explicitly refuses to translate these static addresses into a Linux physical load. Missing or invalid query evidence stays marked unverified. Offline fixture regressions cover foreign digests, providers, query mismatches, malformed addresses, failure payloads, and zero hits without false conclusions.

To inspect only saved existing evidence (NO Ghidra execution and no firmware extraction), run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools/test_y2q_linuxloader_rea_stage4_seeds.py
python3 tools/y2q_linuxloader_rea_stage4_seeds.py
cat ~/s20-artifacts/hxl1-research/abl-linuxloader/rea-stage4-seed-audit.md
```

**Then** choose 1–3 concrete REA-reported analyzed string addresses with strong Android boot-loader relevance. Use the fork's exact `rea xrefs /absolute/path/LinuxLoader-HXL1.efi ADDRESS --provider ghidra --json`, `rea function ... PROCEDURE`, `rea decompile ... PROCEDURE`, and `rea trace-native-values ... PROCEDURE` on discovered enclosing functions. Record exact evidence IDs and input SHA256; do not infer original runtime execution from pseudocode. Use source-linked instructions and actual AArch64 function argument/register flow to determine image placement and the final branch/jump. The EFI's `entryPointRva=0x1000` and `preferredImageBase=0x0` are **EFI executable** metadata, not Linux physical kernel addresses.

**Stage 4 physical kernel placement remains OPEN**, even though the REA/Ghidra toolchain stage is COMPLETE.


## 2026-10-10 11:27 — first real stock LinuxLoader Ghidra string evidence

Owner ran the focused offline saved-evidence auditor at head `2392e93`. **7 of 8 tests passed**; `test_forged_memory_address_rejected` failed because `analyze()` converted a malformed provider coordinate into `UNVERIFIED_EVIDENCE` instead of propagating the intended hard-stop exception. The real HXL1 seed audit nonetheless ran successfully and showed:

- Original `LinuxLoader-HXL1.efi` SHA256 remains `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`. Static Ghidra string search `bootimg` = **0**, `kernel` = **39**, `dtb` = **85**.
- Observed high-relevance debug string `Kernel Load Address: 0x%x\\n` at Ghidra **`0xbc48c`**, source Evidence `ev_951e9be7f91edd05e7f2bea964ae25ee373dc31f86fd7255cb93ba066c82f6af`.
- Observed `KERNEL SIZE : %lx, KERNEL END ADDERSS: %lx DT_LoadAddr: %lx` at **`0xbce52`**; adjacent `Kernel is overlapped with DT` `0xbce90`, allocation failure `Not Enough space left to load kernel image` `0xbcca0`, and `KernelBaseAddr` `0xbd490`.
- Observed `Best match DTB tags ...` at Ghidra **`0xbd674`** and `Exact DTB match found. DTBO search is not required` `0xbd7c4`. Related appends/board DTB selection messages strongly support actual **DTB selection logic** in this LinuxLoader, but **do not yet establish which DTB or its actual runtime physical destination**. Both DTB strings are from Ghidra Evidence `ev_59baeb3c4338999aacf0622efd2699688c849088f74d1f84249a99ef44bcc66a`.

These are original PE **analysis data/string addresses** (not bootloader physical addresses or executable function entrypoints). The print format alone does not give the value printed at runtime. There is no extracted kernel base/physical handoff from this log.

**Test fix** commit `f4356a4`: malformed Ghidra analysis addresses now throw `CorruptEvidenceLocation` from the offline parser and halt the full audit, while legitimately missing/foreign evidence remains explicitly marked unverified. All eight regression cases require owner/CI rerun.

**Targeted next REA step**: `tools/run_y2q_hxl1_stage4_xrefs.sh` invokes only three provenance-checked exact-source `rea xrefs` queries on original loader string addresses `0xbc48c` (kernel load), `0xbce52` (kernel/DT boundary) and `0xbd674` (best DTB match). The script uses the already configured native REA 6.3.0/Ghidra 12.1.4 toolchain and verified PE hash, reuses previously authenticated xref JSON, and writes source analysis addresses and provider evidence IDs to `rea-stage4-xrefs-audit.md`. `tools/y2q_linuxloader_rea_stage4_xrefs.py` validates the target SHA256, Ghidra provider, exact query address and source string prior to reporting references; **10 synthetic tests** added. No guessed function names, runtime address calculation, firmware re-extraction, or device changes.

Single requested WSL command:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -q tools/test_y2q_linuxloader_rea_stage4_seeds.py tools/test_y2q_linuxloader_rea_stage4_xrefs.py
bash tools/run_y2q_hxl1_stage4_xrefs.sh
```

Next stage *after* obtaining real xref **source** instruction addresses: resolve enclosing functions, follow printer arguments with REA decompiler/def-use, inspect kernel Image/boot-v2 placement logic and final ARM64 handoff. **Do not conflate a print-format-string, EFI PE image base 0x0, or EFI entry RVA 0x1000 with a verified kernel physical address.** Stage 4 still OPEN.


## 2026-10-10 11:48 — exact Ghidra xref sources recovered from original LinuxLoader

Owner ran `tools/run_y2q_hxl1_stage4_xrefs.sh` after pulling commit `c8cc910`; **all 18 Stage 4 seed/xref offline regressions PASS**. Exact original `LinuxLoader-HXL1.efi` SHA256 remained `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`. All three direct REA 6.3.0/Ghidra 12.1.4 xref responses independently passed the original binary, source string, query-coordinate and Ghidra-provider checks:

| Observed diagnostic | Original string address | Source instruction of reference | REA xref evidence ID |
|---|---|---|---|
| `Kernel Load Address: 0x%x` | `0xbc48c` | **`0x2178c`** | `ev_eb0ce01cac500bff8b624037fb0f3ffd3e30eebbb649c5143706d34cb98b429e` |
| `KERNEL SIZE : ... DT_LoadAddr...` | `0xbce52` | **`0x216e8`** | `ev_9d11fbe5c2c90b206f319ab27318b944c5d9a0f532f0f47b205c825c810d14f6` |
| `Best match DTB tags ...` | `0xbd674` | **`0x24e18`** | `ev_3a63aab316e4fed9c64a086991569a2b105d50c700d1f445b2e759d88ea564bd` |

Each string had **exactly one** verified reference. The first two xref source instructions are only `0xa4` bytes apart; that does NOT prove they are in the same Ghidra function or that the address printed is a physical Linux load address. The reference to DTB matching is further away and must be independently bound to a function.

**Next direct analysis:** The REA fork's exact Ghidra Java bridge `resolveProcedure` calls `FunctionManager.getFunctionContaining` when given an interior memory address, so `rea function <original EFI> 0x2178c --provider ghidra --json`, etc, can directly retrieve the **enclosing function**. Its `analyze_function` operation returns the function body ranges, decompiler pseudocode, Ghidra assembly and native HighFunction/p-code def-use evidence. `tools/run_y2q_hxl1_stage4_functions.sh` runs exactly **three** such calls on the original xref source instructions, reuses existing validated function dossiers and stops if any output does not authenticate. `tools/y2q_linuxloader_rea_stage4_functions.py` confirms PE hash and original reference, direct Ghidra provider, source-to-function membership and function entry membership in full Ghidra body ranges; saves both full evidence JSONs and a readable `rea-stage4-functions-audit.md`, including any shared function entrypoints. Seven offline regression fixtures added, with execution on owner's host still pending.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_stage4_functions.sh
```

**Engineering limit:** Function and p-code recovery is not evidence of actual execution, runtime physical Linux load, factory ABI, unlocked bootloader, or KernelSU. Next review original Ghidra pseudocode and value-flow provenance before proposing any address.


## 2026-10-10 12:10: Original BootLinux load-layout arithmetic recovered

Owner ran `tools/run_y2q_hxl1_stage4_functions.sh` against genuine SHA256-pinned `LinuxLoader-HXL1.efi`. **Seven/seven** new synthetic function-dossier tests passed and **three** real original REA 6.3.0/Ghidra 12.1.4 function dossiers were authenticated. The previously separate kernel-address and kernel/DT-space diagnostic references are unequivocally in **the same** Ghidra function `FUN_00020a60`, body `0x20a60..0x228df`, with Ghidra HighFunction p-code available. Related selector `FUN_00023bc8`, body `0x23bc8..0x25103`, also has HighFunction p-code. Evidenced original Ghidra IDs:

- `kernel-load-print` `FUN_00020a60`: `ev_506be3a028e265ffb35075507e4277622a0a59578456ffc310586ff5191a3ded`;
- `kernel-dt-boundary` `FUN_00020a60`: `ev_fb7cefe153c76c9bfa8e9171e3522336a8397493d1cbb7c36e8f0b6d98284d47`;
- `best-dtb-match` `FUN_00023bc8`: `ev_9a97905f56a03853dfcc381dd5f99f39c37be72f3fe3a618100c56d28b304229`.

**Now observed in actual firmware code** rather than inferred from a string:
- `FUN_0001f018(&local_1c0)` retrieves a base-memory input (actual runtime value unknown).
- BootLinux obtains `KernelBaseAddr` and `KernelSize` via an indirect UEFI service at `DAT_00351a40 + 0x48`. If *both* queries return success, and the detected kernel is in the recognized ARM64 format, initial kernel target `local_190 = KernelBaseAddr + 0x80000`; alternate image-format branch uses `KernelBaseAddr + 0x8000`. Its region upper end becomes `local_188 = KernelBaseAddr + KernelSize`.
- If either query fails, the fallback `local_190 = (local_1c0 | *puVar1)` selects one of firmware-stored **DAT_000b2210/DAT_000b221c** offset words based on image format, while region upper end becomes `local_188 = local_1c0 + *(DAT_000b2214/DAT_000b2218)`. Note the fallback uses **bitwise OR**, not addition; do not casually replace it with arithmetic addition.
- A firmware KASLR state word `DAT_0032a4c8` contributes `_DAT_a0001004 = DAT_0032a4c8 << 15`, then `local_190 = local_190 + (uint64)_DAT_a0001004`. In the sentinel-equals-`0x40` branch the word is initialized via `FUN_00020838` and masked with `0x3f`, implying a 32-KiB-granularity displacement; the range for other initialization branches and the runtime value are not proved.
- Computes ramdisk and DTB destinations `local_180` and `local_178` below the region upper end, using page-size rounding and a 2-MiB spacing. Performs overlap checks including `local_178 <= local_190` and checks against the kernel runtime image size.
- Decompress path sends `local_190` as a destination to `FUN_00023730(...)`; direct-copy paths call an indirect memory-copy service `DAT_00351a38+0x160` to copy kernel bytes to `local_190`.
- Calls DTB selector `FUN_00023bc8(uVar14,uVar23,local_14c,local_178)`; that function reads `model`, `qcom,board-id`, `qcom,msm-id`, `qcom,pmic-id` from candidate device-tree data. These are selection inputs, not conclusive runtime winning DTB.

**Very important:** `0x80000` is a boot image placement **offset**, NOT a literal physical address. Neither `KernelBaseAddr`, the base-memory input, fixed firmware offset words, nor the KASLR word's actual runtime value is yet in evidence. The main BootLinux source ends beyond the pasted report's 18,000-character preview; neither its final indirect kernel jump nor boot-services exit were shown there.

**New passive next probe:** `tools/y2q_linuxloader_rea_stage4_placement.py` revalidates all three original REA function dossiers, checks that both views of `BootLinux` agree, reports actual observed placement statements and p-code availability, and retrieves the **last 180 lines** of complete Ghidra pseudocode from existing local JSON (NO Ghidra rerun). It saves `rea-stage4-placement-tail.md` and JSON, with explicit unknown runtime values. Eight synthetic offline tests added. This targets the missing final handoff evidence instead of another scan.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -q tools/test_y2q_linuxloader_rea_stage4_placement.py
python3 tools/y2q_linuxloader_rea_stage4_placement.py
sed -n '/## Previously omitted BootLinux pseudocode tail/,/## Still unknown/p' \\
  ~/s20-artifacts/hxl1-research/abl-linuxloader/rea-stage4-placement-tail.md
```

**Additional high-value static input**: the four 32-bit OEM fallback words at Ghidra PE addresses `0x000b2210..0x000b221f` can be read with REA `read-bytes` (16 bytes, original authenticated PE) to resolve *fallback offsets* without a live device or blind scan. That **still would not establish the firmware runtime `BaseMemory` value**. Once the remaining tail is observed, follow any final kernel branch/ExitBootServices callee and its register setup, separately distinguishing static values from runtime state. Stage 4 remains OPEN.


### 2026-10-10: one-command evidence continuation with static OEM values

A narrow operator wrapper `tools/run_y2q_hxl1_stage4_placement.sh` was added to run eight offline regressions, authenticate and extract the existing original `BootLinux` **last 180 pseudocode lines**, and issue precisely two new native REA/Ghidra static-memory reads against SHA256-pinned original `LinuxLoader-HXL1.efi`:

1. `rea read-bytes ... 0xb2210 --length 16`: captures all four contiguous 32-bit OEM fallback offset/size words referenced by `DAT_000b2210`, `DAT_000b2214`, `DAT_000b2218`, `DAT_000b221c`.
2. `rea read-bytes ... 0x32a4c8 --length 4`: captures the **static-image** value of bootloader KASLR state, not the runtime randomized value.

Every result is retained in REA's original JSON Evidence envelope, and the wrapper verifies Ghidra provider, input SHA256, exact query address/length and operation before printing bytes. It does **not** query the physical phone, launch the EFI, modify any firmware, or reuse an unverified output. The original full provider data is under `~/s20-artifacts/hxl1-research/abl-linuxloader/`.

Single next command:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_stage4_placement.sh
```

The current Stage 4 proof obligation is to interpret the original BootLinux tail and identify its actual final kernel branch target/registers and which of the two demonstrated placement branches can execute. A PE RVA, static firmware initialized word, or UEFI variable name is NOT a valid numerical `kernel_phys_load` without its runtime value and correct address domain. **Bootloader unlock, actual privilege elevation, GhostLock viability, and KernelSU are still not demonstrated.**


## 2026-10-10 12:32: Actual static ARM64 boot handoff and OEM fallback constants identified

Owner ran `tools/run_y2q_hxl1_stage4_placement.sh` at `403106e`; all **8/8** placement regression tests passed. All **16** original stock `BootLinux` placement anchors verified. The complete final **180 lines** of original, Ghidra-decompiled `FUN_00020a60` (970 pseudocode lines) were recovered from previously authenticated REA JSON **without rerunning analysis**.

### The final actual *static* control-transfer site is no longer unknown

On successful return from `FUN_0001e868()` (UEFI boot-services shutdown helper), BootLinux calls `FUN_0001e9b8()`, `FUN_0002d878(1)`, then dispatches:

```c
pcVar22 = local_178;         // computed device-tree destination
pcVar24 = local_190;         // computed kernel load/entry destination
if (local_130 == '\0') {
    (*local_190)(local_178, local_1c0,
                 (longlong)local_190 - local_1c0, 0);
} else if (uVar23 == 0) {
    (*local_190)(0, 0, local_178);
} else {
    // firmware-mediated 32-bit mode handoff after state setup:
    pcVar24 = (code *)*DAT_00346b38;
    FUN_0007a024(local_108, local_b8, 0x50);
    lVar13 = (*pcVar24)(local_108);
}
```

The *function-pointer target is exactly* the **same computed `local_190` destination** that receives the kernel decompression or copy. Thus static handoff structure is confirmed; the separate hypothesis of "unknown final jump" is **CLOSED**. This does NOT demonstrate that this branch executed on the original handset at runtime, or that the numerical kernel physical address is known. Keep `kernel_phys_load` UNSET.

### Exactly four little-endian firmware fallback words and initial KASLR state

Original REA Ghidra `read-bytes` on SHA256-pinned stock EFI:

- `0xb2210`, length 16, bytes **`00000800000060050000c00300800000`**, complete, Evidence `ev_4870f8749a2b7c9173591ed0aa49e4fa7be3de0a8b5216923e8f107f1962b95e`. As four little-endian `uint32`:
  - `DAT_000b2210 = 0x00080000` (ARM64 fallback kernel offset, **512 KiB**).
  - `DAT_000b2214 = 0x05600000` (ARM64 fallback memory region size, **86 MiB**).
  - `DAT_000b2218 = 0x03c00000` (alternate-image region size, **60 MiB**).
  - `DAT_000b221c = 0x00008000` (alternate-image fallback kernel offset, **32 KiB**).
- `0x32a4c8`, length 4, bytes **`40000000`**, complete, Evidence `ev_d90aeaf7759363f9b26daf64c0752bc59f286df23ddab01c207acfad87dc32cc`, original **`DAT_0032a4c8 = 0x40`**. This is the static initial KASLR sentinel, **not the runtime random choice**. `FUN_00020838` initializes it during boot and BootLinux masks it to 6 bits in the sentinel branch before computing `KASLRValue << 15`.

Original base-memory/KernelBaseAddr branch equations, conditional on actual OEM boot parameters:

```text
UEFI variable branch (ARM64): KernelEntry = KernelBaseAddr + 0x80000 + (KASLRValue << 15)
Fallback branch (ARM64):      KernelEntry = (BaseMemory | 0x80000) + (KASLRValue << 15)
Firmware region upper end:    BaseMemory + 0x05600000  (fallback ARM64)
```

The **bitwise OR** on fallback is a deliberate verbatim representation of original decompilation; do not silently turn it into `+` unless independently proven equal for the specific runtime BaseMemory. Valid final entry must still satisfy loader's kernel/ramdisk/DT space checks.

### Next actionable proof: dynamic inputs' origin, not another loader scan

The new original-EFI evidence-gated `tools/y2q_linuxloader_rea_stage4_handoff.py` cross-checks verified BootLinux source, the original shutdown-before-jump code ordering, the **three** conditional transfer forms, and both REA `read_bytes` results against the exact SHA256 pinned AArch64 EFI. It documents two distinct classifications: static transfer proven, numeric boot-time entry **unmeasured**. Ten synthetic regressions include tampered constants, wrong REA target and call-graph ordering.

`tools/run_y2q_hxl1_stage4_handoff_sources.sh` then performs only three targeted, cached REA 6.3.0/Ghidra 12.1.4 decompilations on known *original call targets*, preserving full provenance:
1. **`FUN_0001f018` / `0x1f018`** — source that computes `local_1c0` (`BaseMemory`).
2. **`FUN_00020838` / `0x20838`** — KASLR initialization from static `0x40` sentinel.
3. **`FUN_0001e868` / `0x1e868`** — UEFI shutdown helper that gates final jump.

`tools/y2q_linuxloader_rea_stage4_sources.py` verifies SHA256, Ghidra provider, original query address, and real Ghidra function body membership, and publishes `rea-stage4-source-functions.md` plus original full Evidence JSONs. Eight additional synthetic tests cover wrong provider/digest/query/body and unavailable p-code. No device commands or firmware changes.

**Next owner command**:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_stage4_handoff_sources.sh
```

**Stage 4 status:** Final original bootloader kernel handoff *static code path* is now **IDENTIFIED**; numerical `kernel_phys_load` for GhostLock/KernelSU remains **UNVERIFIED**, as do the runtime UEFI/fallback branch and real BaseMemory/KASLR/selected DTB. This evidence neither demonstrates a practical escalation nor unlocks the phone or installs KernelSU.



## 2026-10-10 — physical S20+ connected via ADB; transition to live read-only evidence

The owner reported a real Galaxy S20+ connected to Ubuntu WSL2 with functioning ADB transport. No new device property, physical RAM address, root privilege, kernel trace or DTB read has yet been reported from this ADB session. The previously recovered original **HXL1 ABL LinuxLoader** static control transfer and its OEM fallback constants are the *reference model*, not observed runtime values:

- ARM64 UEFI branch: (KernelBaseAddr + 0x80000) + (runtime KASLR state << 15).
- ARM64 fallback branch: (BaseMemory | 0x80000) + (runtime KASLR state << 15).
- Final direct ARM64 transfer after successful boot-services exit is through local_190 (with DTB at local_178); this is firmware static code, not a measurement of the booted system.
- Kernel boot offset 0x80000, fallback 0x05600000 region size, and initial KASLR sentinel 0x40 are **not** a numerical runtime kernel physical address.

**New HXL1-specific read-only collector**: tools/y2q_live_adb_boot_probe.py. It uses the already known exact-HXL1 identity gates from the project's futex smoke-test runner: SM-G986U1, y2q, G986U1UESCHXL1, exact Android 13 fingerprint, Linux 4.19.113-27095354, locked boot/vbmeta state and UID 2000. It aborts **before optional device probing** if any identity check fails. No root, test binary, futex action, Shizuku API, reboot, flashing, or device write is invoked.

It reads only allowlisted getprop values and ordinary readable kernel/device-tree locations: /proc/cmdline, /proc/bootconfig, /proc/iomem, /proc/device-tree/chosen/bootargs, /sys/firmware/devicetree/base/chosen/bootargs, DT root model from both exposures, and read-only kptr_restrict/dmesg_restrict. It does not dump an entire property namespace or a raw DTB; potentially identifying bootargs and seed/key-like tokens are redacted before persistence. Permission denials and missing files are first-class results, not evidence of address zero. Nonzero /proc/iomem ranges are still not conclusive evidence of the original BootLinux jump's physical target.

**Operator commands (with physical phone authorized for USB debugging):**

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    adb devices -l
    python3 -m unittest -q tools/test_y2q_live_adb_boot_probe.py
    python3 tools/y2q_live_adb_boot_probe.py

With more than one authorized ADB device:

    python3 tools/y2q_live_adb_boot_probe.py --serial YOUR_ADB_SERIAL

The serial is used only for command routing, never written in the report. Outputs are stored in a new UTC-timestamped subdirectory below ~/s20-artifacts/hxl1-research/live-adb/, with owner-only mode on report files. Inspect the resulting live-boot-evidence.md. Re-running uses a distinct UTC directory rather than overwriting previous evidence.

If stock Android denies /proc/iomem or hides the device-tree bootargs, document the absence and continue the already-targeted **static provenance** investigation of FUN_0001f018 (BaseMemory), FUN_00020838 (KASLR source), and FUN_0001e868 (UEFI boot-services shutdown) using tools/run_y2q_hxl1_stage4_handoff_sources.sh. Do not interpret WSL2 host /proc/iomem as phone memory, do not attempt to read /dev/mem, and do not bypass Android security protections just to force a value.

**Still not verified:** firmware variable branch actually selected, per-boot BaseMemory, KASLR value, matching DTB, numerical physical kernel entry, usable exploit primitive, root or KernelSU. The device probe is observational only.


## 2026-10-10 13:00 UTC — live phone ADB evidence: unprivileged memory access blocked

The owner attached the **physical** SM-G986U1 through WSL2 ADB. Manual commands and the exact-HXL1 identity gate independently returned **SM-G986U1**, **G986U1UESCHXL1**, kernel **4.19.113-27095354**, and ADB `uid=2000(shell)` with SELinux context `u:r:shell:s0`. No elevated privileges or firmware changes were attempted.

After pulling commit `3889301`, `python3 -m unittest -q tools/test_y2q_live_adb_boot_probe.py` returned **12/12 PASS**. The on-device, identity-gated, read-only collector passed and saved a timestamped report at `~/s20-artifacts/hxl1-research/live-adb/20261010T130008Z/live-boot-evidence.md`. Report contents beyond the printed command summaries have **not** yet been supplied to the repository.

Observed permission status, directly from the physical S20+:

| Source | Observed status |
|---|---|
| `/proc/cmdline` | PERMISSION_DENIED |
| `/proc/bootconfig` | NOT_PRESENT |
| `/proc/iomem` | PERMISSION_DENIED |
| `/proc/device-tree/chosen/bootargs` | PERMISSION_DENIED |
| `/sys/firmware/devicetree/base/chosen/bootargs` | PERMISSION_DENIED |
| `/proc/device-tree/model` | PERMISSION_DENIED |
| `/sys/firmware/devicetree/base/model` | PERMISSION_DENIED |
| `/proc/sys/kernel/kptr_restrict` | PERMISSION_DENIED |
| `/proc/sys/kernel/dmesg_restrict` | PERMISSION_DENIED |

Collector correctly classified `/proc/iomem` as **UNAVAILABLE**, not zero. Neither WSL host `/proc/iomem` nor phone ADB shell can currently supply a verified live physical kernel-entry address. Shizuku starting from shell UID 2000 would not, by itself, change those permissions.

**Decision:** Stop repeating these restricted Android reads. Continue original EFI *static* source attribution, which does not require privilege escalation, with the already committed `tools/run_y2q_hxl1_stage4_handoff_sources.sh`. It targets only `FUN_0001f018` (BaseMemory input provenance), `FUN_00020838` (KASLR state source), and `FUN_0001e868` (UEFI ExitBootServices path). A successful decompilation can narrow the set of possible placement conditions; it cannot claim the actual boot-time BaseMemory, KASLR or selected UEFI branch absent separate trustworthy live/firmware evidence.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_stage4_handoff_sources.sh
```

**Device-specific Stage 4 status:** correct locked HXL1 target VERIFIED; static BootLinux placement and ARM64 handoff code VERIFIED; live physical base/KASLR/DTB selection **UNAVAILABLE**, numeric `kernel_phys_load` UNVERIFIED; GhostLock exploit viability, root and KernelSU installation UNVERIFIED. No device-memory bypass or device operation is justified by this evidence alone.


## October 10, 2026 — Genuine REA source dossiers on HXL1 and safe ADB preflight

Owner submitted complete output from tools/run_y2q_hxl1_stage4_handoff_sources.sh and the futex smoke binary preflight (host report dated 20261010T130932Z). The REA pass returned **18/18 regression tests PASS** and verified the original ARM64 handoff plus the original four fallback words. All three new exact-original-EFI Ghidra source dossiers passed provider/PE SHA256/function body verification.

- FUN_0001f018, body 0x1f018–0x1f1a3 (REA ev_e245a9baee51343ff77969723209b40f324422a08bace6cc2148ec130ec8dd24), invokes FUN_0001eca0(&local_30,&local_34), checks the returned status and processes a RAM-partition base pointer/count. Writes a derived value to *param_1 and can print "Memory Base Address: 0x%x". The decompiler shows complicated array/minimum selection, including compiler-vectorized-looking logic; **do not assert that it always selects the lowest physical partition base without understanding descriptor layout and control-flow details**.
- FUN_00020838, body 0x20838–0x20927 (REA ev_d30c985627eaa4f4da9fca86ecba8265bf5efe9067d7e1df47734c6247c46ba0), invokes UEFI BootServices protocol lookup via DAT_00351a38+0x140 and a located protocol method at +8 to request pseudorandom bytes. Both lookup and acquisition have explicit failure logging; actual output, mask and runtime KASLR displacement are **not measured**.
- FUN_0001e868, body 0x1e868–0x1e9b3 (REA ev_8d4701c2d6176bb67c8627e120c2d1b634d865985924c0dc61e7397fbce5389b), acquires UEFI memory map through DAT_00351a38+0x38, retries memory-map buffer allocation when needed, and calls ExitBootServices through DAT_00351a38+0xe8 using the map key. Actual branch execution remains unobserved.

The owner also ran the project’s AArch64 futex-PI smoke diagnostic **--preflight-only**. It verified the specific local ELF SHA256 e7506a3f5ef3f323e278b83ec353354298f7f1c74a6972efbddd3f5b70c54412, physical phone identity, UID=2000 and enforcing SELinux. Its status was **PREFLIGHT_ONLY**, not syscall execution, exploitation, root or KernelSU.

**Next distinct static evidence:** FUN_0001eca0 itself (the Qualcomm RAM-partition reader). The source-audit SOURCES tuple and one-command tools/run_y2q_hxl1_stage4_handoff_sources.sh now add this single specific REA function analysis; the other three dossiers are cached and reused. The new tools/y2q_linuxloader_rea_ram_partition_chain.py stores original authenticated caller and reader pseudocode, evidence IDs and function entrypoints with an explicit numeric runtime BaseMemory **unknown**. New tests check reader ownership, absence/forged outputs, missing call, and no invented physical address. The wrapper no longer needlessly republishes the previous long three-function/hand-off reports.

Exact next host step (no phone writes/firmware unpacking):

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_stage4_handoff_sources.sh

Inspect the report rea-stage4-ram-partition-chain.md and inspect its RAM table descriptor layout and provider protocol before assuming numerical ranges or loading addresses. The live Android UID 2000 interfaces /proc/iomem, /proc/cmdline and DT chosen bootargs are **PERMISSION_DENIED**, so keep kernel_phys_load UNVERIFIED. Additional nonroot futex-PI execution is a separate, opt-in diagnostic and would not establish a GhostLock vulnerability.


## 2026-10-10 13:27 — On-device safe futex prerequisites PASS; original EFI RAM protocol read verified

The owner ran `bash tools/run_y2q_hxl1_stage4_handoff_sources.sh` with head `b7f1252`. **27/27** offline unit tests PASSED, all three previously authenticated REA/Ghidra source dossiers were correctly cached and reused, and one new exact original LinuxLoader function `FUN_0001eca0`, body `0x1eca0–0x1eee7`, was successfully decompiled. Ghidra source evidence ID: `ev_3368790f6a1b8ce33a5fc47bfb0dc5d44f0a82919c1e897e93aa67255021d2f9`.

### Exact original RAM partition source chain

`FUN_0001f018(&BaseMemory)` invokes `FUN_0001eca0(&local_30, &local_34)` to obtain a pointer/count and then processes the base addresses at 16-byte strides. The called firmware routine:

1. Checks cached `DAT_00346ad8` for an existing RAM partition array.
2. If absent, resolves an EFI protocol using GUID data at **`DAT_000ef880`**, with LocateProtocol through BootServices+0x140.
3. Calls the protocol function at **`(local_50 + 0x18)`** first with no output buffer to obtain the required RAM-partition count, handling `EFI_BUFFER_TOO_SMALL`.
4. Allocates exactly `DAT_00346ae0 << 4` bytes = **16 × entry count**, then calls the same function again to populate the buffer; on failure frees the allocated data.
5. Returns the validated array pointer through `*param_1` and count through `*param_2`, caching both for subsequent reads.

An external copy of the Qualcomm protocol header, `EFIRamPartition.h`, declares `RamPartitionEntry` as `UINT64 Base; UINT64 AvailableLength` (16-byte total), and positions `GetRamPartitions` at protocol+0x18. Reference: https://www.cnblogs.com/schips/p/qualcomm_about_uefi.html . This independently agrees with the genuine ELF's allocation and Base-entry traversal. The public header defines GUID **`5172ffb5-4253-7d51-c641-a701f973103c`**. However, the actual 16 GUID bytes at the original `LinuxLoader` address `0xef880` have **not yet been read**; do not claim that GUID identity is verified until the next probe completes.

### Physical S20+ uncontended futex-PI syscall smoke

Separately the user **opted in** and executed the existing safe diagnostic once on their exact HXL1 Galaxy S20+ as ADB UID 2000, SELinux Enforcing. ELF SHA256 `e7506a3f5ef3f323e278b83ec353354298f7f1c74a6972efbddd3f5b70c54412`; on-device stdout:

- `FUTEX_WAIT_PRIVATE` mismatch: PASS, `errno=11` (EAGAIN).
- `FUTEX_WAKE_PRIVATE` with no waiters: PASS, `rc=0`.
- `FUTEX_LOCK_PI_PRIVATE` uncontended and `FUTEX_UNLOCK_PI_PRIVATE`: PASS, correct owner TID and zero state restored.
- `FUTEX_TRYLOCK_PI_PRIVATE` uncontended and unlock: PASS, correct owner and zero state restored.
- `RESULT=PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY` and host status `SAFE_PI_PREREQUISITES_VERIFIED_NOT_ROOT`.
- The staging executable was removed successfully. Host report: `~/s20-artifacts/y2q-futex-pi-smoke-20261010T132706Z.json`.

These are **basic syscall prerequisite tests** only; no concurrency, race, requeue, real GhostLock exploit, kernel information leak, root or KernelSU operation was attempted or demonstrated. Do not repeat this exact safe test unless a new question warrants it.

### Next singular original-EFI proof

The new `tools/run_y2q_hxl1_ram_partition_protocol.sh` is a **host-only** Ghidra static probe of the exact protocol GUID at PE-analysis address `0xef880`, length 16, against already-known original stock EFI SHA256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`. It reuses all original REA function dossiers and only reads a single GUID. `tools/y2q_hxl1_ram_partition_protocol_audit.py` checks Ghidra provenance, exact pointer/callsite, count×16 allocation, caller 16-byte traversal, correct EFI GUID byte order and published protocol value before certifying the ABI. Ten additional fixture tests cover forgery, mismatched GUID/read, and missing caller/reader evidence.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ram_partition_protocol.sh
```

Expected host output location: `~/s20-artifacts/hxl1-research/abl-linuxloader/rea-stage4-ram-partition-protocol.md`. If the GUID differs, stop and investigate; a generic Qualcomm header is not proof that Samsung's stock HXL1 vendor protocol has the same GUID. Even when the GUID is confirmed, no original XBL protocol **implementation**, runtime partition data or numerical physical kernel base is established by ABL alone.

**Stage 4 state:** Original UEFI RAM partition source flow and static kernel handoff verified; live BaseMemory/physical kernel entry **UNVERIFIED**. GhostLock exploitability **UNVERIFIED** despite clean futex-PI prerequisites.


## 2026-10-10 13:38 — real HXL1 EFI_RAMPARTITION protocol GUID/ABI VERIFIED

The owner ran `bash tools/run_y2q_hxl1_ram_partition_protocol.sh` against the original, SHA256-pinned stock `LinuxLoader-HXL1.efi`, with **17/17** synthetic tests passing.

- Exact source: PE SHA256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`.
- REA 6.3.0 / Ghidra 12.1.4 `read_bytes` at static PE address **`0xEF880`**, length **16**, confirmed GUID **`5172ffb5-4253-7d51-c641-a701f973103c`**, with evidence ID `ev_f40a34471b26b4710436e575866b7a2a2dee173a3d19854da13c67aca3ac4813`.
- Original `FUN_0001eca0` uses the UEFI `LocateProtocol` entry at `BootServices+0x140`, then calls the protocol's `GetRamPartitions` function at `protocol+0x18`. It queries required count first, then allocates **16 × partition count** and fetches actual partition records.
- Original `FUN_0001f018` consumes the 16-byte descriptors and derives a firmware `BaseMemory` value for later `BootLinux` placement logic. Public Qualcomm protocol `RamPartitionEntry` ABI: `UINT64 Base` at offset 0 and `UINT64 AvailableLength` at offset 8. The original stock GUID and ABI agree with the public `EFIRamPartition.h`. Reference: https://www.cnblogs.com/schips/p/qualcomm_about_uefi.html .

**Protocol ABI now verified in the actual stock ABL consumer.** Crucially, this is not proof of the implementation location, runtime partition count/entries, success of protocol registration on the phone, `BaseMemory`, selected KASLR branch, or a numerical kernel physical load address.

### Provider-side next target: XBL DXE firmware EnvDxe candidate

Public Qualcomm bootloader source descriptions locate `SetupRamPartitionProtocol` in `boot_images/QcomPkg/Drivers/EnvDxe/EnvDxe.c`, which creates `RamPartitionProtocol` and registers `gEfiRamPartitionProtocolGuid` via `InstallMultipleProtocolInterfaces`. This is a **reference implementation location**, not proof the original Samsung HXL1 binary includes a literal uncompressed EnvDxe module at a known offset. References: https://www.cnblogs.com/linhaostudy/p/18358956 and https://www.cnblogs.com/schips/p/qualcomm_about_uefi.html .

Original stock inputs have already been identified and SHA256-pinned by `tools/y2q_stock_bl_elf_audit.py`:

- `~/s20-artifacts/hxl1-research/bl-stock/xbl.elf` — `78d1bff9ef5c2aa626652390c112f0bf81869bb1f9a05fcd8a8e3dfff8f8b357`.
- `~/s20-artifacts/hxl1-research/bl-stock/xbl_config.elf` — `757fc6ef87134283d37fa4ee57f5180e3849107e216f48f379323ce473f40d7f`.

New `tools/y2q_hxl1_xbl_ram_guid_locator.py` performs a **targeted byte-exact** EFI GUID lookup in only these two original local ELFs, validating their existing SHA256 and ELF identity first. It reports original file offsets and whether the result falls within a PT_LOAD file-backed segment; any ELF virtual coordinate refers to **XBL itself, not the Linux kernel**. It records canonical-order bytes separately to avoid accidentally treating reversed GUID bytes as UEFI objects. **No literal match is still inconclusive**, because DXE firmware contents may be compressed, nested, or not directly visible in PT_LOAD file bytes. A GUID match alone does not prove the registering function.

Ten offline fixture tests and `tools/run_y2q_hxl1_xbl_ram_guid_locator.sh` were added. Execute exactly once on the WSL2 host:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_xbl_ram_guid_locator.sh
```

Output: `~/s20-artifacts/hxl1-research/xbl-rampartition/original-xbl-rampartition-guid.md`. If a genuine 16-byte little-endian GUID is present within an original XBL ELF load segment, investigate the containing firmware module/actual registration xrefs. If absent, perform only a *targeted* firmware-volume/decompression inspection for the named provider driver, not a repeat of broad DTB/FDT/image surveys. Root/KernelSU remain absent; physical kernel load remains unverified.


## 2026-10-10 13:45 — original XBL RAM GUID absent in raw files, next targeted DXE inspection

Owner ran the previously committed tools/run_y2q_hxl1_xbl_ram_guid_locator.sh. All **10 synthetic regressions passed**. Both original stock files passed existing SHA256/ELF identity pins, but the exact EFI_RAMPARTITION GUID 5172ffb5-4253-7d51-c641-a701f973103c had **0 literal matches in each file**, in both EFI little-endian and canonical binary form.

- xbl.elf: SHA256 78d1bff9ef5c2aa626652390c112f0bf81869bb1f9a05fcd8a8e3dfff8f8b357; 0 literal GUID matches.
- xbl_config.elf: SHA256 757fc6ef87134283d37fa4ee57f5180e3849107e216f48f379323ce473f40d7f; 0 literal GUID matches.

This rules out those **literal byte sequences in the original packed ELFs**, not the provider's existence in nested/compressed volumes, a separately embedded XBL_CORE, or a constructed GUID. Do not repeat identical raw-GUID scans.

**Next bounded original-firmware step:** tools/y2q_hxl1_xbl_envdxe_fv_probe.py. The existing validated ABL UEFI FV/FFS/GUID-LZMA Walker is reused to inspect the already-pinned original XBL bytes. An additional strictly bounded gzip candidate decoder validates CRC/stream end before accepting an internal FV. Inspected EFI PE payloads are classified only for the exact RAM protocol GUID or related EnvDxe/RamPartition/EFI_RAMPARTITION strings; FFS/UI identification and each accepted PE's hash and FV trace are retained. No EFI executables are written to disk, no phone connection or device modification is involved, and no value is promoted to a runtime physical base.

**Important limitation:** Raw ELF GUID absence, no valid FV, or no qualifying gzip member is **not** proof that Samsung's original DXE provider is missing. Tiano, alternate vendor compression, raw XBL_CORE layout, or protocol GUID construction may require a separate targeted investigation. A decoded matching GUID proves only a candidate until actual registration function/xrefs are shown.

External format references: https://github.com/linux-msm/xbltools and https://worthdoingbadly.com/qcomxbl/ . Other Qualcomm models' gzip layout is a research lead, not a demonstrated HXL1 fact.

13 synthetic tests and the branch CI workflow now cover the focused inspector. Operator command:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_xbl_envdxe_fv_probe.sh

Output: ~/s20-artifacts/hxl1-research/xbl-rampartition/original-xbl-envdxe-fv.md . If a candidate module is found, next verify its uncompressed original PE's callsites and protocol installation. If not, use the reported FV/gzip counts to choose one *different* compression/layout path, not another generic scan.

Current limits: original ABL protocol ABI and static ARM64 kernel handoff verified; exact XBL provider, boot-time RAM partitions, BaseMemory, runtime KASLR, numerical kernel physical entry, GhostLock viability and KernelSU remain unverified.

## 2026-10-10 13:53 — original EnvDxe executable located in XBL gzip firmware volume

The owner ran **tools/run_y2q_hxl1_xbl_envdxe_fv_probe.sh** at commit d6d84a0; **13/13 regressions passed**, original XBL SHA256 and ELF pins passed. These are actual HXL1 original-firmware observations, not synthetic fixture data:

- Original **xbl.elf** SHA256 78d1bff9ef5c2aa626652390c112f0bf81869bb1f9a05fcd8a8e3dfff8f8b357; 4,194,304 bytes; one direct, validated FV (0 recognized AArch64 PEs), one CRC-checked gzip member starting at original ELF file offset **0xc6488**.
- Decompressed gzip contains one nested valid FV, **93 AArch64 PE32+ executables** recognized by original FV/FFS walker. **EnvDxe** has FFS GUID **90a49afd-422f-08ae-9611-e788d3804845**, extracted PE SHA256 **9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670**, and original `EFI_RAMPARTITION` GUID in PE file bytes at offset **0xd118**. Original PE includes `EnvDxe` and `RamPartition` strings. This is **CANDIDATE_BINARY_CONTAINS_PROTOCOL_GUID**, not confirmed protocol-registration code.
- **DisplayDxe** at FFS GUID 4138022f-06c7-4f79-9c94-7e33b511a4e7 / PE SHA256 facaa8938acd61d1f9d06434504268c139cf02d8378f78d673c38a550f1174c0 contains `RamPartition` string only, no GUID; lower priority.
- Original **xbl_config.elf** SHA256 757fc6ef87134283d37fa4ee57f5180e3849107e216f48f379323ce473f40d7f; no direct FV, gzip stream or EnvDxe candidate.
- The original xbl outer FV includes an unhandled GUID-defined section e9... that does not invalidate the independently decompressed and verified EnvDxe. Do not infer the provider is globally exhaustive based on this subset parser.

**Next distinct evidence gate, no phone involvement:** tools/y2q_hxl1_extract_envdxe.py recovers only this original EnvDxe PE from pinned XBL and exact gzip offset; requires the exact original FFS GUID, recovered PE SHA256, GUID content at 0xd118, and a valid AArch64 PE32+ header; writes one artifact EnvDxe-HXL1.efi (no executable run), provenance manifest and static PE file-offset-to-RVA mapping. tools/run_y2q_hxl1_envdxe_rea_xrefs.sh first reads back **16 bytes** from the PE's *actual REA/Ghidra static import address*, requiring exact original GUID bytes and original PE digest; only then calls REA `xrefs` once on that validated address, caching authenticated evidence. A byte mismatch is a **HARD STOP**: Ghidra import bases can differ from PE preferred image base, and zero xrefs must never be taken as proof of no installer at an unverified address.

Operator command:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_rea_xrefs.sh

Outputs in ~/s20-artifacts/hxl1-research/xbl-rampartition/: EnvDxe-HXL1.efi, original-envdxe-hxl1.md, rea-envdxe-ram-guid-xrefs-audit.md (if verified). **No device memory accessed, no firmware writes, no root attempt.** The RAM-partition provider function and its installer remain unverified until the actual code references, decompilation and call pattern are corroborated. Even a proven installer cannot supply boot-time RAM values from the firmware binary alone. Physical Linux kernel entry, GhostLock viability and KernelSU remain open.


## 2026-10-10 14:12 — original EnvDxe extracted; valid GUID byte readback and ZERO direct Ghidra xrefs

User ran `tools/run_y2q_hxl1_envdxe_rea_xrefs.sh` against exact original HXL1 XBL. **23/23** offline regressions PASS.

- Exact original **EnvDxe PE** recovered from XBL gzip/FFS, SHA256 `9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670`. File: `~/s20-artifacts/hxl1-research/xbl-rampartition/EnvDxe-HXL1.efi`.
- PE file offset and section RVA for original Qualcomm RAM protocol GUID: both **`0xd118`**, with preferred original static VA `0xd118`. SHA256-verified PE extraction and offset-to-RVA mapping completed.
- REA 6.3.0 / Ghidra 12.1.4 **read_bytes at `0xd118` returned the exact 16-byte little-endian GUID**. Evidence ID `ev_74de6870e702b91b73346d03fc6a97b30bb98f413a4b894ac6ce8adf5bc316e3`; confirms the Ghidra imported program's byte at that coordinate is the right target, not merely a guessed file offset.
- Direct REA/Ghidra `xrefs` of that same verified coordinate returned **ZERO** original source references; evidence ID `ev_5ff67c28ffa587f70fe81f43606c28e72d303300c650e426be4234bdaf1ac24a`. This is a **valid negative for Ghidra's direct xref model**, NOT a demonstration that this module never constructs or uses that GUID, and NOT evidence against provider installation.

This result closes the previous uncertainty about module provenance and wrong static image base. The next step must change the investigative dimension, not simply repeat the same zero-xref query. A Qualcomm reference `boot_images/QcomPkg/Drivers/EnvDxe/EnvDxe.c` implementation registers the RAM partition protocol after initialization through UEFI `InstallMultipleProtocolInterfaces`; external context at https://www.cnblogs.com/linhaostudy/p/18358956 . This is **reference** source, not evidence that the exact Samsung binary uses the same implementation or symbols.

**New distinct host-only REA probe**: `tools/run_y2q_hxl1_envdxe_entry_strings.sh` keeps the exact original EnvDxe SHA256 and both authenticated GUID readback / zero-xref records as hard preconditions. It reads and authenticates the original **PE entryPointRva and preferredImageBase** from the extraction manifest (rechecked against the actual original PE header), calls REA/Ghidra `function` exactly once on that entry, and runs only three literal, case-insensitive, Ghidra `search --kind strings` patterns: **RamPartition**, **GetRamPartitions**, **EnvDxe**. Each original function/string Evidence result is checked against PE SHA256, Ghidra provider, operation, original input address/literal and valid static coordinates; cached authenticated results are reused, conflicting/partial ones are never overwritten. The report retains complete original entrypoint decompilation and exact diagnostic string addresses.

`tools/y2q_hxl1_envdxe_entry_strings.py` and **13 synthetic regressions** added, CI wired. The next checkpoint is the driver's entrypoint call tree or *actual observed* diagnostic string xref(s), not protocol installation claimed from a GUID literal alone. Run:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_entry_strings.sh

Report: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-entry-strings-audit.md`. If the entrypoint or searches cannot be authenticated, report the exact gap and inspect the original REA saved JSON. **Do not invent dynamic firmware partition bases, per-boot KASLR, runtime kernel_phys_load, root or KernelSU.**


## October 10, 2026, 14:24 UTC — original EnvDxe entrypoint validated; RAM-partition table strings recovered

Owner executed tools/run_y2q_hxl1_envdxe_entry_strings.sh after updating to commit f8ed48c. **All 13 synthetic tests passed**. The original EnvDxe PE SHA256 is **9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670**; the earlier exact-GUID REA readback and **zero direct GUID xrefs** remained authenticated.

New actual original-Ghidra evidence:

- PE entry `0x1000`, Ghidra function `entry` at `0x1000`, HighFunction p-code available; evidence ID `ev_6e9f1cc76c0eb2c339a47b5f1bc4dcf864cbda2f84f423528af76880a7d2098e`. Its decompiled control flow makes two distinct calls: `FUN_000010f4()` for driver/runtime initialization and `FUN_00001150(...)` for the main driver initializer. The source observed two callees, zero callers. Neither call is yet proven to register EFI_RAMPARTITION.
- Ghidra `search_strings` for RamPartition: **2** matches: `0xa87e` = `RamPartitionTableLib.c`, and `0xa895` = `mRamPartitionTableEntryCount <= 4`; evidence ID `ev_0844542ffbb6954d1356e88a2bcf533a309fdfc20735842a56b8bc36902d1b2b`. The assertion indicates compiled code checking a **<=4** bound; it is NOT an observed runtime entry count and supplies no numerical RAM base.
- Ghidra search for GetRamPartitions: **0** strings; evidence ID `ev_fbc59b6cb6449dddbd54577438fd28093e32b19b4f58efa191e4a3680a0f66fe`. Absence of literal compiled function name is NOT evidence of function absence.
- Ghidra search for EnvDxe: **1** at `0x90bf` = `EnvDxe.c`; evidence ID `ev_80c4f38fbf6400b57c67ee8a89adf5170457ba154668aefc488228d0c1b514fc`.

**Next precise original PE step** in the same existing branch: `tools/run_y2q_hxl1_envdxe_ram_source_xrefs.sh`, targeting xrefs of exactly the three proven original strings at `0xa87e`, `0xa895`, `0x90bf`, plus authentic original REA/Ghidra function dossiers for the two entrypoint direct calls at `0x10f4` and `0x1150`. Each REA result is checked for original EnvDxe SHA256, Ghidra provider, operation and requested address, and actual body membership (for function queries); the full pseudocode is retained. Cached verified evidence is reused; conflicting/partial evidence is never overwritten. **14 additional synthetic fixtures** test wrong hash/provider/query, invalid references, absent pseudocode, Ghidra-body validity and non-promotion of zero xrefs to absent installation. CI is wired.

Operator commands (no phone needed):

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_ram_source_xrefs.sh

Report: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-ram-source-xrefs.md`.

This changes investigative dimensions from absent GUID xrefs to actual startup function call tree and diagnostic strings. Next proof is the exact firmware initializer path to `InstallMultipleProtocolInterfaces` and the actual GetRamPartitions callback implementation. Even proving both functions statically does not provide XBL runtime DRAM partition entries, UEFI KernelBaseAddr variable values, actual per-boot KASLR, device physical kernel load address, exploitability or KernelSU.


## 2026-10-10 14:32 — EnvDxe Ghidra RAM-table diagnostic xrefs and startup-call chain

The owner ran `bash tools/run_y2q_hxl1_envdxe_ram_source_xrefs.sh` on branch commit `32f0076`. All **14 synthetic tests passed**. The original, SHA256-pinned HXL1 XBL `EnvDxe-HXL1.efi` is still SHA256 `9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670`. Original REA/Ghidra evidence: actual `EnvDxe` entrypoint `0x1000`; exact GUID bytes at `0xd118`; zero direct GUID xrefs, as previously observed.

**New, authenticated static sources:**

- The original source diagnostic `RamPartitionTableLib.c` (`0xa87e`) has **two** Ghidra xrefs from instructions `0x554c`, `0x572c`. REA evidence ID `ev_b7cbec4f1b33bfe4cdc33b6645b89349f6bd6e34e35d34c0eaef9032c194ed42`.
- The `mRamPartitionTableEntryCount <= 4` assertion text (`0xa895`) has **two** Ghidra xrefs from `0x5554`, `0x5734`. REA evidence ID `ev_db2936b04e50fb1e7b7f372a21b6fb0e6c1e8bca598ca7df37409ba646773125`.
- `EnvDxe.c` (`0x90bf`) has **nine** xrefs at `0x1818`, `0x1870`, `0x1a10`, `0x1be4`, `0x1d70`, `0x1df4`, `0x1e70`, `0x1ec8`, `0x232c`. REA evidence ID `ev_b5033c4218f1a2c00659933d0f3ee85c72160f5d15f729cbec3d795388b09103`.
- Genuine Ghidra `FUN_000010f4` uses `DAT_0000d000 = thunk_FUN_000051a4()`, HighFunction true. REA evidence ID `ev_9b8a5baa949e5855d2c1ef3e4d0e0a3154bc31184795110731cf5f0f9099ad17`.
- Genuine Ghidra `FUN_00001150` calls `FUN_0000123c`, then `thunk_FUN_000022b0` and on error `FUN_00001500`; HighFunction true. REA evidence ID `ev_c5e3ef2b05dc8eccfb50cbdf1a33c9ed949bce104f34b278975fe0d10aa6aae9`.

The two RAM-source xref **instruction pairs** are at `0x554c/0x5554` and `0x572c/0x5734`, each 8 bytes apart. These strongly motivate checking the containing function bodies, but the current evidence alone does **not** establish that each pair belongs to one Ghidra function, that there are two distinct RAM parsing routines, or that those addresses contain physical RAM values. The `<=4` string is a compiled assertion, not a measured active partition count.

**Next verified-function gate implemented:** `tools/y2q_hxl1_envdxe_provider_followup.py` plus host wrapper `tools/run_y2q_hxl1_envdxe_provider_followup.sh`. This revalidates all prior exact-original-PE SHA256 and REA source evidence and issues precisely **three** REA/Ghidra function requests: `0x22b0` (init dispatch), `0x554c` and `0x572c` (RAM-table diagnostic reference sources). For RAM-table regions, the returned Ghidra function body must include **both** the matching source-file and assertion instruction addresses before its pseudocode is accepted. A function whose body splits the pair is a **hard stop** requiring revised address-specific inspection. Actual Ghidra function ranges, original evidence IDs and complete pseudocode are saved; any observed indirect calls or callbacks are still considered unverified until directly traced. The report does not promote function names, references or compiler assertions to runtime physical address evidence.

The update includes **16 synthetic tests**, CI compile/unit/shell checks, and preserves existing evidence rather than overwriting it. Run on WSL2 (the phone is not used):

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_provider_followup.sh

Report: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-provider-followup.md`.

Even if registration code is eventually identified, an original static PE is not a live DRAM partition-table dump. Runtime `BaseMemory`, KASLR, the booted Linux physical entry, GhostLock exploitability and KernelSU installation remain unverified.


## October 10, 2026 14:42 — original EnvDxe RAM-table supplier and conditional fallback located

Owner ran `bash tools/run_y2q_hxl1_envdxe_provider_followup.sh` at commit `48a377c`. **16/16 offline tests passed**. All three authentic SHA256-verified original EnvDxe HXL1 PE Ghidra function dossiers passed native function-body ownership and p-code availability.

Actual recovered function evidence:

- Original `FUN_000022b0` (`0x22b0`) is an EnvDxe startup dispatch that calls `FUN_0000422c` for a pointer and runs many initializer candidates, including `FUN_000023b0` and `FUN_000020ac`; provenance `ev_28d41ca312f2b314f1b34321f95fc763af7a851427fd8cc69434200a86e3d2d6`.
- Original `FUN_00005430` at `0x5430` contains both earlier validated diagnostic reference source instructions `0x554c`, `0x5554`. It processes a 0x40-stride input table, matching fields at +0x2c == 1 and +0x24 == 0xe, accumulates table records in `DAT_0000d6d8`-based state, and asserts at most four RAM-partition entries. **No actual runtime table contents were read**. Provenance `ev_71558580cd7ebcdb9318eacfb416cdd69b68024d089d546790a5128f73c795c9`.
- Original `FUN_00005560` at `0x5560` contains both source instructions `0x572c` and `0x5734`. It invokes `FUN_000053b0` to obtain a pointer/descriptor format and handles two 0x40-/0x48-stride table layouts; it also applies the at-most-four-entry bound. Provenance `ev_a9198391b279aafa76b364535bdffcc763c9a060d9abccdcd9b7bbe115c42fd7`.
- Crucially, under **one explicit error-status condition** `FUN_00005560` assigns `DAT_0000d700 = 0x60000000` and `DAT_0000d6f8 = 0x80000000`. These are **original static compiled fallback constants**, NOT observed device runtime RAM boundaries or confirmed interpretation of which field is Base and which is AvailableLength.

### Porting maturity

The device is the original locked-US `SM-G986U1` exact HXL1 phone. Full-target firmware identity and safe ADB shell/read-only probe are proven. The uncontended futex-PI syscall smoke passed on the physical phone as UID 2000. Original ABL handoff code and original compressed XBL EnvDxe module are verified. This project is nevertheless in **device-specific research and exploit-feasibility analysis**, **not a working Root-My-Galaxy payload port**. There is no verified vulnerability trigger, race, leak, kernel write primitive, safe in-memory kernel patch, root, persistent privilege or KernelSU module deployment for this stock locked handset. Neither ADB nor Shizuku shell access yields those privileges.

### Next targeted host-side probe

Three new grounded functions need original SHA256-authenticated REA/Ghidra dossiers: `FUN_000053b0` (direct table supplier called by `0x5560`); `FUN_000023b0` and `FUN_000020ac` (startup initialization candidates called by `0x22b0`). A single authenticated REA/Ghidra xref query at **`0x5560`** will also identify static callers of the table initializer, without inferring that any caller ran on the physical phone. These are candidates only, not claimed protocol registration. New `tools/y2q_hxl1_envdxe_ram_table_input_trace.py`, 16 synthetic tests, a bounded runner and CI checks were committed. Execute in WSL2 **without attaching the S20+**:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_ram_table_input_trace.sh

Report: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-ram-table-input-trace.md`. It will preserve full source function pseudocode and evidence IDs. The actual kernel physical load address, runtime KASLR slide and root exploit remain **UNVERIFIED**, regardless of static address constants.


## 2026-10-10 14:56 — SMEM usable RAM partition item #402 identified in authentic XBL EnvDxe

The owner executed `bash tools/run_y2q_hxl1_envdxe_ram_table_input_trace.sh` at commit `383f18a`. All **16/16 synthetic tests PASS**. In the original SHA256-pinned `EnvDxe-HXL1.efi` PE (`9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670`) the following specific REA/Ghidra static observations have been verified:

- `FUN_000053b0` (evidence `ev_a8306fc1926b94396bfbc973686d0f596380e9a6abe0a6fc98f7a1b029b11f6e`) invokes `FUN_00007d08(..., 0x192, &local_24,...)` to obtain shared-memory data, then `FUN_00005288(piVar1, param_10)` checks its layout/version. `0x192` = decimal 402, and a publicly published Qualcomm rampart.h defines `SMEM_USABLE_RAM_PARTITION_TABLE 402`. This is an independently corroborated **static shared-memory table identifier**, not a live RAM table. Source: https://www.mail-archive.com/u-boot@lists.denx.de/msg564611.html .
- A Ghidra xrefs query of original `FUN_00005560` returned exactly **one** reference instruction `0x2064` (evidence `ev_488f21c6cbea40876162cea5864bccd27ebd0cce17992b7b86cb8e17486117cd`). It remains to inspect the function containing this instruction before claiming startup execution.
- Original `FUN_000023b0` (evidence `ev_8364d6cc9d69f009700adf42c74d84ddba130ebe24058a3899e83850a7d87442`) invokes an indirect method from `DAT_0000d328 + 0x80` using the GUID pointer `&DAT_0000d2e8` and interface pointer `&DAT_0000d178`. The **UEFI 64-bit BootServices offset +0x80 corresponds to InstallProtocolInterface**, not InstallMultipleProtocolInterfaces (+0x148), if DAT_0000d328 is the EFI_BOOT_SERVICES pointer. This call's GUID data differs in static **address** from the already verified EFI_RAMPARTITION GUID at `0xd118`; do not claim the GUID **value** is different until the original 16 bytes at `0xd2e8` are read and compared. External reference: https://www.lightbulbone.com/posts/2018/03/uefi-ninja/ and https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html .
- `FUN_000020ac` (evidence `ev_f30bb26959450f72b6241d10f16cf7fac5ca8e8ff881908484cb8c2930695cb3`) calls `FUN_00004ecc` and conditionally copies a config field to `DAT_0000d320 +0x20`; it is not yet proven to register any protocol or supply RAM partitions.

**Next narrow read-only REA audit committed:** `tools/y2q_hxl1_envdxe_smem402_protocol.py` and `tools/run_y2q_hxl1_envdxe_smem402_protocol.sh`. The tool re-verifies all previous original SHA256/evidence and reads exactly **16 bytes at Ghidra 0xd2e8**, then decodes its EFI GUID and compares its bytes to the validated RAM protocol GUID at `0xd118`. It also decompiles exactly three original, callsite-grounded functions: `0x2064` (original sole RAM-table initializer reference), `0x5288` (SMEM RAM table header/format validation called by `0x53b0`), and `0x7d08` (shared-memory accessor called with item 402). These target addresses are **original static PE addresses**, not Linux kernel physical addresses. Original SHA256, requested REA operations, Ghidra provider, function body inclusion and imported GUID read length/identity are required before a PASS. Even if `0xd2e8` matches the RAM GUID, registration still requires verifying boot-services pointer provenance/callback. If it differs, this branch is a different EFI protocol and we should not mislabel it as the RAM installer. 14 new synthetic tests and CI checks are included.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_smem402_protocol.sh

Report: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-smem402-protocol.md`.

**Explicitly unresolved:** whether and where the original XBL registers EFI_RAMPARTITION, the runtime SMEM table content, numerical BaseMemory, boot-time KASLR and kernel physical load, GhostLock exploit applicability and privilege escalation, and KernelSU installation. No ADB needed or used in this host-only stage.


## October 10, 2026 15:14 — original EFI_RAMPARTITION registration path located, double evidence/test throughput

Owner executed `bash tools/run_y2q_hxl1_envdxe_smem402_protocol.sh` on original, SHA256-pinned stock `EnvDxe-HXL1.efi` PE `9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670`. **15/15 synthetic tests passed**, and all original REA/Ghidra source dossiers and GUID readback checks passed. The command reused original JSON from a previous host analysis; results were reauthenticated rather than claimed newly measured.

### Key finding: genuine original RAM protocol registration branch

- At original Ghidra coordinate **`0x205c`**, the real `FUN_0000205c` calls original **`FUN_00005560`** (RAM table initialization). On **success only** it executes the decompiled indirect call `(**(code **)(DAT_0000d328 + 0x148))(0xd2b8,0xd118,0xd1d0,0,0)`. REA evidence `ev_194f166b1d738a6a1d6320693288ee282d8892de32d02f809de891fdfdd57c74`; the earlier one-reference Ghidra xref to 0x5560 at `0x2064` independently led to this function.
- Offset `+0x148` matches `EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces` on UEFI x64/AArch64 ABI; arguments match HandlePointer `0xd2b8`, protocol GUID pointer **`0xd118`**, interface pointer **`0xd1d0`**, and terminating `NULL` GUID. These match the UEFI Specification's GUID/interface-pair calling convention; reference https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html . The **16 original bytes at 0xd118** were previously authenticated as Qualcomm EFI_RAMPARTITION GUID `5172ffb5-4253-7d51-c641-a701f973103c`.
- This is **strong, consistent original-static evidence for the RAM protocol registration callsite, conditional on successful table initialization**. Runtime boot-service identity, registration return status and execution on the physical device have NOT been observed.
- The separate `FUN_000023b0` calls method `+0x80` using GUID data at `0xd2e8`, which authenticated Ghidra readback shows to be **16 zero bytes** (GUID `00000000-0000-0000-0000-000000000000`), evidence `ev_fee50b9de8b5cc65d8154061849127ea1c73f0cd72c3a04923a4732743ecb7ce`. This *does not directly pass the genuine RAM GUID*. It is a separate initialization path; do not promote it to the RAM installer.
- `FUN_00005288` at `0x5288` validates the SMEM 402 RAM-partition header through two fixed 32-bit magic values and writes format/version to the caller; evidence `ev_29cc7adb5126cc64599526d6507c784b971bae83259e0ba5b81f7c26a21bb1dd`.
- `FUN_00007d08` at `0x7d08` is the actual SMEM accessor; on initialized SMEM it forwards the item argument through a function pointer and returns its address, evidence `ev_fff9072b258237dedae47b40ac58c2211dc3680efd13d304ab642cf55d40e461`. In earlier parent function 0x53b0 this argument is **0x192**, the public Qualcomm usable RAM-partition table identifier 402.
- Physical base and length reported by this runtime SMEM item are **unavailable from static PE disassembly**. The fallback 0x80000000/0x60000000 remains conditional. The original ABL protocol consumer's GetRamPartitions method is at **interface +0x18**, so the decisive next question is the published static interface's +0x18 callback address and original code.

### Double-rate next pass

User requested at least **twice the testing rate per pass**, because sequential tiny investigations were too slow. New `tools/y2q_hxl1_envdxe_ram_registration_callback.py` and `tools/run_y2q_hxl1_envdxe_ram_registration_callback.sh` combine **two distinct evidence groups into one host run**:

1. Gate the authentic `0x205c` registration pseudocode, the exact `0xd118` RAM GUID from prior byte-verified evidence, success branch, UEFI method +0x148, exact interface address 0xd1d0, and reject the separate all-zero candidate 0xd2e8 as RAM registration.
2. Read **48 exact original Ghidra bytes** at 0xd1d0. Interpret six little-endian qwords and the method slot **+0x18, static coordinate 0xd1e8**. Query **eight** targeted Ghidra xrefs: interface 0xd1d0, callback slot 0xd1e8, RAM installer function 0x205c, SMEM402 table supplier 0x53b0, 0x5430 RAM v1 parser, 0x5288 format validator, 0x7d08 generic SMEM accessor, and unrelated 0x23b0 protocol initializer. If the method's raw qword is plausibly a nonzero word-aligned static PE address, immediately obtain and SHA-bind the actual Ghidra function dossier. Otherwise report relocation/uninitialized static slot as an explicit gap, never "callback absent."

The audit uses exact original PE SHA256, earlier REA evidence IDs, readback length, Ghidra provider and requested coordinates, callback function-body containment, and fail-closed reuse of cached JSON. It cannot contact or modify the handset.

**45 independent synthetic regression tests** are committed in two new suites (23 registration/interface + 22 callback/reference), over **2.8×** the previous 15-test pass; CI includes test and shell syntax checks. The actual WSL2 run has not yet occurred.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_ram_registration_callback.sh

Output: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-ram-registration-callback.md`.

This resolves provider-side **registration source code**, not runtime table contents, selected device DRAM base, ABL per-boot KASLR, kernel physical entry, GhostLock exploit reliability, Samsung RKP/KDP/DEFEX restrictions, or KernelSU deployment. Nothing currently makes the HXL1 Root My Galaxy research profile installable.


## October 10, 2026 15:30 — 45 regression PASS, real report-schema gate defect corrected

Owner executed `tools/run_y2q_hxl1_envdxe_ram_registration_callback.sh` after pulling `cae2c98`. **45/45 synthetic tests passed in 0.144 s**, then **before performing the first new Ghidra query**, the stage aborted with:

    [STOP] Prior static evidence was promoted without runtime proof

This is an **audit implementation defect**, not indication that RAM was read at runtime or that a root primitive was obtained. The new code checked `previous.get("numericRuntimeRamBaseMeasured") is not False` against the direct output from `y2q_hxl1_envdxe_smem402_protocol.audit`. That key belongs to the **grandparent** `y2q_hxl1_envdxe_ram_table_input_trace.audit`, not the direct previous report, whose actual keys are:

- `efiRamProtocolRegistrationProven: False`
- `ramProtocolImplementationRegistrationConfirmed: False`
- `physicalBaseMemoryMeasured: False`
- `runtimeSmemTableContentsObserved: False`
- `kernelPhysicalLoadVerified: False`

Python dict `.get` returned `None` for the missing `numericRuntimeRamBaseMeasured` key; `None is not False` triggered the false-positive abort. Source code was fixed to check **all five actual direct parent fields**, preserving fail-closed semantics when a required field is missing or `True`.

The earlier suite mocked the entire prior report and therefore did not catch upstream schema drift. To prevent recurrence, the repaired tests now include an **actual full prior `smem402_protocol.audit` execution using synthetic original REA evidence**; only its still-earlier input report is stubbed. The downstream registration check consumes that **real immediately upstream result**, including the absence of grandparent-only keys. Additional regressions assert failure on actual boot-time observation flags and invalid original registration callsite pseudocode. Total suite grew from **45 to 57 tests** across three suites; all are in the CI workflow.

Run the corrected host-only stage again:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_ram_registration_callback.sh

The first new actual Ghidra query will read the original 48-byte protocol interface at static `0xd1d0`, then eight authentic bounded xref queries, and optionally decompile the original `GetRamPartitions` callback at slot `+0x18` when a valid static address exists. **No runtime physical RAM, KASLR, GhostLock exploitation, KernelSU or root has been proven.** The user's S20+ is not required for this offline test.


## October 10, 2026 15:52 — original RAM protocol callback discovered: 0x1f74; Ghidra decompiler failure is NON-FATAL

Owner executed `bash tools/run_y2q_hxl1_envdxe_ram_registration_callback.sh` after pulling `1573f67`. The command printed `Ran 72 tests in 0.192s / OK` even though the banner said `57`: a test module inadvertently imported the whole 15-test `Hxl1Smem402ProtocolTests` subclass into unittest's discovery namespace. This was harmless double execution, **not 72 independent regression scenarios**. Corrected by importing the test-fixtures *module*, not the class, in `tools/test_y2q_hxl1_envdxe_ram_registration_parent_chain.py`.

The original firmware evidence is now significantly stronger:

- Original SHA256-pinned `EnvDxe-HXL1.efi` (`9502aa29ce9c1081833d763d56e42b999a181c146b827f907a2c6ba9a3481670`) verified the genuine, **conditional** `FUN_0000205c` RAM-protocol installer at PE address `0x205c`, REA `ev_194f166b1d738a6a1d6320693288ee282d8892de32d02f809de891fdfdd57c74`.
- The exact **48 original imported bytes** at protocol interface `0xd1d0` were authenticated via Ghidra. The `+0x18` method slot at **`0xd1e8`**, consumed by original ABL's `GetRamPartitions` call, is a nonzero raw little-endian pointer **`0x1f74`**. These static coordinates are original PE RVA/preferred VA, NOT observed boot-time physical or virtual DRAM.
- **Eight of eight** original Ghidra xrefs queries authenticated successfully. Direct references: interface 0xd1d0 **0**, callback slot 0xd1e8 **0**, installer at 0x205c **1**, SMEM402 supplier at 0x53b0 **2**, RAM v1 parser at 0x5430 **1**, SMEM header checker 0x5288 **1**, SMEM getter 0x7d08 **2**, other-protocol installer 0x23b0 **1**. These xref counts do not demonstrate execution at boot.
- The optional direct `REA function 0x1f74 --provider ghidra` failed. **No Ghidra error message was included in the terminal output**, so the failure cause (missing function discovery, provider exception, decompiler error, etc.) is *not established*. Runner preserved `rea-envdxe-ram-protocol-callback-function.partial.json` and `rea-envdxe-ram-protocol-callback-function-stderr.txt`; it previously aborted without emitting the aggregate result. Do not equate decompilation failure to a missing callback.
- No physical S20+ connection required; only original firmware and read-only host tools were used.

### Corrective combined fallback: independent ORIGINAL PE bytes, not another brittle decompile gate

New `tools/y2q_hxl1_envdxe_callback_raw_proof.py` validates the exact original EnvDxe PE SHA256, preferred PE base, unambiguous section RVA->raw-offset mapping at `0x1f74`, **PE IMAGE_SCN_MEM_EXECUTE** on its owning section, 4-byte AArch64 alignment, and a bounded **64-byte original instruction SHA256/hex**. This binary-mapping verification is independent of whether Ghidra recognizes a function.

New host runner then attempts a single `node "$REA" read-bytes "$EFI" 0x1f74 --length 64 --provider ghidra --json`, compares the 64 imported Ghidra bytes **exactly** to those from the SHA256-pinned original executable section, and records the original REA evidence ID. A failed imported-byte read is preserved as a partial and reported unresolved, but cannot erase the independent original-PE evidence.

The earlier failed Ghidra function-analysis partial/stderr are reused as **failure evidence**, included with bounded SHA256 and diagnostic excerpt in `rea-envdxe-ram-registration-callback.md`, and are **not overwritten or retried automatically**. An invalid completed function dossier remains fail-closed. If the callback's raw pointer is not a unique executable-section coordinate, the PE-mapping test fails, rather than inventing code location or callback behavior. Reports distinguish: (1) original executable bytes proven, (2) imported byte match, (3) decompilation still unavailable, and (4) live callback invocation unknown.

The expanded regression suite uses 57 prior distinct cases, plus 3 callback-failure report scenarios, 19 independent PE/REA raw-proof checks, and 42 targeted evidence/section mutation scenarios for **121 distinct test methods**, more than double the 57-test previous intended suite. GitHub CI includes compile/unit tests and runner syntax.

Run in WSL2 (NO S20+ needed):

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_ram_registration_callback.sh

Report: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-ram-registration-callback.md`. **Original 0x1f74 callback function semantics, live SMEM partition entries, BaseMemory, actual kernel physical load, KASLR, GhostLock privilege escalation, and KernelSU remain unverified.** A zero direct Ghidra xrefs count to an initialized interface slot does not disprove data-pointer identity.


## 2026-10-10 16:07 — original EFI RAM +0x18 callback executable and static BL to 0x52cc authenticated

The owner ran `bash tools/run_y2q_hxl1_envdxe_ram_registration_callback.sh` at `ff54319`. **121/121 offline regression tests PASS**. The original SHA256-pinned stock HXL1 `EnvDxe-HXL1.efi` byte read and eight Ghidra xrefs all pass.

**Crucial original PE observation:** The verified protocol interface at `0xd1d0` consists of six little-endian UINT64 values:

    +0x00 0x10001
    +0x08 0x1ee8
    +0x10 0x1f0c
    +0x18 0x1f74     <-- GetRamPartitions (original ABL consumer ABI)
    +0x20 0x1f28
    +0x28 0x10001

Ghidra REA byte-read evidence of original interface: `ev_e835b6d905f02ab46a655f9708492664caf4ad996c491232e4f41c6f0e328d91`. The independently original-PE-mapped `0x1f74` is a 4-byte-aligned executable ARM64 address in original PE `.text`, PE file offset `0x1f74`. 64 code bytes SHA256 `7d4e16e4b3402ff3959080b7ca298f46c5b9b963b6ddd59203a613948d0d12ef`. Original PE SHA256 and Ghidra imported code agree *byte for byte*; REA evidence `ev_9788b87fef00b57e962287af87496caa03bb7bcb19a238ed658ff1a9a41d0197`.

Ghidra `analyze_function 0x1f74` failed with a specific, preserved native REA error:

    code=invalid_request
    details.operation=analyze_function
    details.issues[0].message="No procedure exists at the requested address: 0x1f74"

This means **Ghidra has not defined a function at 0x1f74**, not that original code or an EFI callback is missing. There is no confirmed decompilation, static function extent or runtime invocation. Failed result SHA256 `d3c979af5bdcf86731ccf884927844c064c48e7076a07936f419fca1e077dbea`; original stderr empty.

By independently decoding the **user-provided, original SHA-verified 64 ARM64 bytes**, the callback begins with normal stack-frame setup, stores input registers, checks an argument, and contains a direct ARM64 `BL` at original static address **`0x1fa4`** with instruction word `0x94000cca`. Architecturally, `BL` encodes a signed 26-bit word-relative displacement. Applying that displacement to `0x1fa4` yields a **firmware code target `0x52cc`**. This is an original firmware static code-reference, not a runtime kernel memory address. The callback's semantics/returned RAM table and chosen boot-time physical values remain unproven.

Previously validated eight Ghidra xref query results: direct xrefs to interface 0xd1d0 0, GetRamPartitions slot 0xd1e8 0, registration function 0x205c 1 (source 0x22e0), SMEM 402 supplier 0x53b0 2 (0x55b0,0x5770), RAM v1 parser 0x5430 1 (0x5634), table header validation 0x5288 1 (0x53e4), SMEM accessor 0x7d08 2 (0x53d4,0x81f4), other protocol initializer 0x23b0 1 (0x22f4). Zero direct Ghidra references to interface static data are not proof it is unused.

### Combined next host-only pass (more than twice prior test rate)

`tools/y2q_hxl1_envdxe_method_arm64_trace.py` plus `tools/run_y2q_hxl1_envdxe_method_arm64_trace.sh` audit **all four original protocol method pointers** and the **direct callback BL target `0x52cc`**, each through a SHA256-pinned, uniquely executable PE section 128-byte raw window and independent original Ghidra import readback; plus bounded xref queries at callback `0x1f74` and callee `0x52cc`. Its little-endian ARM64 control-flow decoding reports direct `BL/B/B.cond/CBZ/CBNZ/TBZ/TBNZ`, indirect `BLR/BR` and `RET`, with precise static byte addresses and branch targets. **128-byte windows must not be mistaken for full function bodies**. Original source identities and callback's first 64-byte digest remain prerequisite gates. A Ghidra decompiler function definition is not required.

The combined test runner executes the prior 121 independent regression cases plus around 196 new ones: approximately **317 distinct host-only unit checks in one pass**, more than doubling the earlier 121-case pass, with 5 independent code-window reads and 2 xref queries. A failed optional imported byte request is preserved as partial and the exact original PE proof stays usable; a conflicting saved completed result is fail-closed. CI is wired for source compile, unit tests and shell syntax.

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    bash tools/run_y2q_hxl1_envdxe_method_arm64_trace.sh

Expected report: `~/s20-artifacts/hxl1-research/xbl-rampartition/rea-envdxe-four-method-arm64.md`. It will contain four original method windows, original direct callee code window, static ARM64 branch targets and two xref sets. Phone NOT required. This extends original **static** XBL provider evidence; do not infer runtime DRAM entries, physical kernel load, exploit success or KernelSU. Follow this with the more decisive Linux 4.19 structure/layout and GhostLock applicability proof gates before claiming a working Root My Galaxy payload.
