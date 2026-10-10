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
