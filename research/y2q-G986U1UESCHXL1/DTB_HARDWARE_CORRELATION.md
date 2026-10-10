# HXL1 stock Kona DTB — physical SoC identity correlation

**Date:** 2026-10-10 (owner-provided WSL2 and ADB results)  
**Firmware:** SM-G986U1 / G986U1UESCHXL1 / Android 13 / Linux 4.19.113-27095354  
**Status:** **static hardware-identity match only; neither selected running DTB nor physical kernel handoff verified.**

This supplements `docs/SM-G986U1-G986U1UESCHXL1.md`. The HXL1 original `boot.img` and embedded DTB region were previously SHA256-verified and passed all 10 semantic FDT tests, with four contiguous structurally valid FDT trees. The owner independently extracted four original candidate DTBs from the checksum-pinned boot image and verified their SHA256 and full FDT structure before running `fdtget`.

## Stock DTB root metadata

`fdtget -t x` output is hexadecimal, not decimal.

| Candidate | Stock root model | `qcom,msm-id` (hex u32 cells) | `qcom,board-id` | Root compatible | Interpretation |
|---|---|---|---|---|---|
| 1 | Qualcomm Technologies, Inc. kona v2.1 SoC | `0x164 0x20001` | `0x0 0x0` | `qcom,kona` | SoC ID 356, hardware revision 2.1 |
| 2 | Qualcomm Technologies, Inc. kona v2 SoC | `0x164 0x20000` | `0x0 0x0` | `qcom,kona` | SoC ID 356, hardware revision 2.0 |
| 3 | Qualcomm Technologies, Inc. kona v1 SoC | `0x164 0x10000` | `0x0 0x0` | `qcom,kona` | SoC ID 356, hardware revision 1.0 |
| 4 | absent | absent | absent | absent | Minimal valid 173-byte FDT, purpose still unknown |

`qcom,pmic-id` and `qcom,oem-id` are absent at the root of all four candidates. A missing property is **not** an error in the pinned source structure.

## Live physical S20+ (ordinary ADB shell, no root)

```text
uid=2000(shell) context=u:r:shell:s0
SELinux: Enforcing
/sys/devices/soc0/soc_id: 356       # decimal = 0x164
/sys/devices/soc0/revision: 2.1
/sys/devices/soc0/machine: KONA
/sys/devices/soc0/family: Snapdragon
/sys/devices/soc0/platform_subtype: Unknown
/sys/devices/soc0/platform_version: 65536  # decimal = 0x10000
/sys/devices/soc0/foundry_id: 1
/proc/device-tree/model: Permission denied
/proc/device-tree/compatible: Permission denied
/sys/firmware/fdt: UNAVAILABLE to ADB shell
```

The live `soc_id` and revision match the first candidate's legacy `qcom,msm-id` tuple exactly. Its `qcom,board-id` is the same as candidates 2 and 3, so this property does not distinguish the three here. `platform_version` is a separate hardware property; **do not mistake `0x10000` for the running SoC revision**. The observed `foundry_id` must not be silently inferred from a `qcom,msm-id` first cell whose foundry bits are zero.

Qualcomm's older DT binding documentation explains legacy `qcom,msm-id` as a chipset identity and a best-match hardware revision, and notes that bootloader selection may involve further board/foundry rules. References:
- https://android.googlesource.com/kernel/msm.git/+/android-msm-bullhead-3.10-n-preview-1/Documentation/devicetree/bindings/arm/msm/msm-id.txt
- https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/arm/qcom.yaml

**Evidence classification: `CANDIDATE_1_STATIC_SOC_REVISION_MATCH`.** Bootloader-selected DTB is **NOT VERIFIED**. The running FDT could be changed by bootloader fixups, and the manufacturer's exact HXL1 DTB selection policy was not independently established. No physical Linux kernel load address, KASLR, memory mappings, root exploit prerequisites, or KernelSU implementation are inferred.

## Independent Stage 3 DWARF correction

Owner reran `tools/test_y2q_dwarf_type_presence.py`: **10/10 PASS**. The corrected analyzer reported:

| Type | ARM64 partial-build objects checked | Verified complete definitions | Ambiguous/tool error |
|---|---:|---:|---|
| `rt_mutex_waiter` | 77 | 0 | 1, `scripts/mod/empty.o` (`TOOL_ERROR`) |
| `rt_mutex` | 77 | 0 | 1, `scripts/mod/empty.o` (`TOOL_ERROR`) |

The previous broad `pahole` exit-code-only loop produced false positives. No verified full type definition was found in the retained experimental Clang18 partial build. This finding does **not** establish Samsung factory Clang10 structure layouts, their absence from the actual kernel, or vulnerability applicability. Stage 3 remains **PARTIAL**.

## Next bounded research actions

1. **Offline only:** inspect the small fourth FDT's two root property names and values through `dtc -I dtb -O dts`. Retain its unknown purpose unless the contents establish more.
2. **Offline only:** compare the three large DTB root properties and selected harmless device identity metadata. Preserve full original candidate hashes; avoid copying any physical addresses into a target profile.
3. Preserve ADB permission denials as a result. Do not seek elevated shell permissions just to read `/proc/device-tree` or `/sys/firmware/fdt`.
4. Treat the incomplete experimental DWARF pass as closed for now; pursue independent matching debug information only if available. Do not infer stock binary layouts from this attempt.
5. Keep Stage 4 physical handoff `OPEN`, Stage 3 `PARTIAL`, Stage 7 KernelSU `BLOCKED`, and publication disabled.

No firmware was flashed, no device files were written, no module was loaded, and no privilege escalation was attempted in this stage.
