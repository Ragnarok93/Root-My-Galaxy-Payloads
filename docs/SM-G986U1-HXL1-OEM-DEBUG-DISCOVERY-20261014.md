# SM-G986U1 HXL1 — OEM debug-symbol artifact discovery gate
**Checkpoint:** 2026-10-14 UTC. Offline evidence inventory, not a root or exploit demonstration.

## Confirmed evidence

The owner-supplied SHA-pinned stock configuration \`ec6da4cfe412f7d0669c7d621751753375e32197a2602f98627eb95e71b9c0b2\` includes:

- \`CONFIG_DEBUG_INFO=y\`
- \`# CONFIG_DEBUG_INFO_SPLIT is not set\`
- \`CONFIG_LTO_NONE=y\`
- \`CONFIG_CLANG_VERSION=100006\`
- \`CONFIG_BUILD_SALT=""\`

This means the preserved source configuration did **not request split-DWARF .dwo outputs**. A missing \`.dwo\` is therefore not a meaningful blocker in itself; prioritize independent OEM-matching \`vmlinux\` / unstripped non-split DWARF over an open-ended \`.dwo\` hunt. This config finding does not establish exact runtime OEM compiler flags or prove what debug files Samsung retained.

\`abi-dwarf-audit.tar.gz\` contains the previously authenticated reconstructed stock ELF section listing with exactly eight entries: \`.kernel\`, \`.kernel2\`, \`.bss\`, \`.symtab\`, \`.strtab\`, \`.shstrtab\`, \`.rela.dyn\`, plus the null section. **No \`.debug_info\`, \`.BTF\`, \`.gnu_debuglink\`, or \`.note.gnu.build-id\` is present in that reconstructed ELF's section table**. This reconstructed ELF is not the same artifact as OEM linker output. The QEMU normal/KASAN comparison ELFs have their own build IDs and are **not** factory debug-symbol matches.

A targeted public search located Samsung's [Open Source Release Center](https://opensource.samsung.com/) and third-party listings of exact **G986U1UESCHXL1** firmware (for example [SamFW DSH build](https://samfw.com/firmware/SM-G986U1/DSH/G986U1UESCHXL1)). No verified public OEM HXL1 unstripped \`vmlinux\` / separate DWARF package was established. Firmware listing identity alone is insufficient to authenticate symbol artifacts.

## New read-only discovery automation

\`tools/y2q_hxl1_oem_debug_discovery.py\` performs a bounded filename scan of explicitly selected filesystem roots. It reads at most the ELF64 little-endian headers, section index, section-name table, and small debug-link sections for candidate files; it does not execute or load them. Its classification refuses to promote QEMU/KASAN builds or reconstructed \`stock-vmlinux.elf\` to factory provenance. It flags \`.debug_info\`, \`.BTF\`, \`.gnu_debuglink\`, and \`.note.gnu.build-id\` section presence as *candidates*, not proof of OEM identity.

Local verification on the files uploaded to this conversation: **69 directory entries checked, 0 filename-matching ELF candidates**, scan not truncated. This result covers only the uploaded attachments and **does not** claim the owner's WSL filesystem was scanned. **9/9 synthetic tests passed locally**: ELF detection, debug-section classification, comparison-vs-factory separation, symlink handling, bounded traversal and HXL1 config consistency. GitHub Actions completion remains unverified.

Run only once on existing WSL working directories:

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_oem_debug_discovery
OUT="$HOME/s20-artifacts/hxl1-research/oem-debug-inventory-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 tools/y2q_hxl1_oem_debug_discovery.py \
  --root "$HOME/s20-artifacts" \
  --root "$HOME/src" \
  --max-depth 7 \
  --output "$OUT"
printf 'Review generated inventory: %s\n' "$OUT"
~~~

The report includes \`truncated\`; if true, absence of a candidate is not exhaustive even within those roots. No compilation, disassembly extraction, phone interaction, firmware change, payload generation, or privilege request occurs.

## Decision gates

| Evidence prerequisite | Current disposition |
|---|---|
| HXL1 original configuration and no-split-debug selection | VERIFIED from uploaded config |
| Reconstructed stock ELF debug sections / debug locator | NOT PRESENT in captured ELF section table |
| Independently verified OEM-matching DWARF artifact | NOT FOUND in examined evidence; broader search remains open |
| Rebuilt QEMU DWARF factory equivalence | NOT ESTABLISHED |
| OEM compiled local-variable stack locations | UNVERIFIED |
| Cross-syscall stack reuse / GhostLock operation / KernelSU | UNVERIFIED / BLOCKED |

This discovery gate identifies potential source artifacts only. It cannot replace original OEM debug metadata, make a reconstructed ELF equivalent to original linker output, or demonstrate a working root path.
