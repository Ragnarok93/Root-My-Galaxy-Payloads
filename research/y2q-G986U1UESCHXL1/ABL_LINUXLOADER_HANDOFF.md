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
