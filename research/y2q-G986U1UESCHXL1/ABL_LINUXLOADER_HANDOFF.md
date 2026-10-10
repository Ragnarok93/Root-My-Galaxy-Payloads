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
