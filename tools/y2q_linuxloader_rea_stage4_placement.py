#!/usr/bin/env python3
"""Trace cached original HXL1 BootLinux function placement and remaining tail.

No new Ghidra run, firmware modification or inference of physical RAM from
static PE code coordinates. Requires original SHA256-bound REA dossiers.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.y2q_linuxloader_rea_stage4_functions import analyze as validate_functions
from tools.y2q_linuxloader_rea_stage4_xrefs import LOADER_SHA256, AuditError

ANCHORS = (
    ("base_memory", r"FUN_0001f018\(&local_1c0\)"),
    ("uefi_kernel_base", r'L"KernelBaseAddr"'),
    ("uefi_kernel_size", r'L"KernelSize"'),
    ("arm64_image_bias", r"lVar13\s*=\s*0x80000;"),
    ("alternate_image_bias", r"lVar13\s*=\s*0x8000;"),
    ("uefi_variable_placement", r"local_190\s*=\s*\(code\s*\*\)\(lVar13\s*\+\s*local_118\)"),
    ("fallback_placement", r"local_190\s*=\s*\(code\s*\*\)\(local_1c0\s*\|\s*\*puVar1\)"),
    ("kaslr_shift", r"_DAT_a0001004\s*=\s*DAT_0032a4c8\s*<<\s*0xf;"),
    ("kaslr_addition", r"local_190\s*=\s*local_190\s*\+\s*uVar14;"),
    ("ramdisk_region", r"local_180\s*=\s*local_188\s*-"),
    ("dt_region", r"local_178\s*=\s*\(code\s*\*\)\(local_180\s*-\s*\(ulonglong\)\(local_164\s*\+\s*0x200000\)\)"),
    ("range_guard", r"local_178\s*<=\s*local_190"),
    ("decompression_to_destination", r"FUN_00023730\("),
    ("direct_kernel_copy", r"\(local_190,pcVar24,local_160\)"),
    ("kernel_load_log", r'"Kernel Load Address: 0x%x'),
    ("dtb_selection_call", r"FUN_00023bc8\(uVar14,uVar23,local_14c,local_178\)"),
)
DTB_PROPS = ("qcom,board-id", "qcom,msm-id", "qcom,pmic-id", "model")
MAX_CODE = 350000
TAIL_LINES = 180


def context(code: str, pattern: str) -> dict:
    match = re.search(pattern, code)
    if match is None:
        return {"observed": False, "line": None, "excerpt": []}
    line = code.count("\n", 0, match.start())
    lines = code.splitlines()
    return {"observed": True, "line": line + 1,
            "excerpt": lines[max(0, line - 2):line + 3]}


def original_dossier(folder: Path, label: str) -> dict:
    path = folder / ("rea-stage4-function-" + label + ".json")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 50000000:
        raise AuditError("Missing or oversized original Ghidra function Evidence")
    ev = json.loads(path.read_text())
    if (not isinstance(ev, dict) or ev.get("operation") != "analyze_function"
            or ev.get("provider", {}).get("id") != "ghidra"
            or ev.get("subject", {}).get("digest", {}).get("sha256") != LOADER_SHA256):
        raise AuditError("Original Ghidra Evidence provenance mismatch")
    result = ev.get("normalized_result")
    if not isinstance(result, dict):
        raise AuditError("Missing original function dossier")
    return result


def trace(folder: Path) -> dict:
    record = validate_functions(folder)
    funcs = record["functions"]
    if (len(funcs) != 3 or any(x["status"] != "VERIFIED_FUNCTION" for x in funcs)
        or record["sharedFunctions"] != [
            {"entry": "0x20a60", "labels": ["kernel-load-print", "kernel-dt-boundary"]}]
        or next(x["entry"] for x in funcs if x["label"] == "best-dtb-match") != "0x23bc8"):
        raise AuditError("Original exact Ghidra owning function identity not established")
    main = original_dossier(folder, "kernel-load-print")
    other = original_dossier(folder, "kernel-dt-boundary")
    dtb = original_dossier(folder, "best-dtb-match")
    code, code2, dt_code = (x.get("pseudocode") for x in (main, other, dtb))
    if (not all(isinstance(x, str) for x in (code, code2, dt_code))
        or code != code2 or max(map(len, (code, code2, dt_code))) > MAX_CODE):
        raise AuditError("BootLinux pseudocode differs across authenticated Ghidra observations")
    flow = main.get("native_value_flow")
    if not isinstance(flow, dict) or not isinstance(flow.get("available"), bool):
        raise AuditError("Ghidra HighFunction p-code status unavailable")
    flow_info = {}
    for k, v in list(flow.items())[:16]:
        if isinstance(v, list):
            flow_info[k] = {"kind": "array", "count": len(v)}
        elif isinstance(v, dict):
            flow_info[k] = {"kind": "object", "keys": list(v)[:16]}
        elif isinstance(v, (str, int, float, bool)) or v is None:
            flow_info[k] = v
    return {
        "classification": "VERIFIED_STATIC_ORIGINAL_HXL1_BOOTLINUX",
        "loaderSha256": LOADER_SHA256,
        "bootLinuxFunction": "0x20a60",
        "dtbSelectionFunction": "0x23bc8",
        "placementStatements": {name: context(code, pattern) for name, pattern in ANCHORS},
        "dtbProperties": {p: context(dt_code, re.escape('"'+p+'"')) for p in DTB_PROPS},
        "highFunctionMetadata": flow_info,
        "bootLinuxTotalLines": len(code.splitlines()),
        "bootLinuxTail": code.splitlines()[-TAIL_LINES:],
        "numericPhysicalLoadVerified": False,
        "kernelHandoffVerified": False,
        "runtimeDtbSelectionVerified": False,
        "deviceModified": False,
    }


def render(result: dict) -> str:
    items = [
        "# Original HXL1 BootLinux placement and control-transfer evidence",
        "",
        "Original HXL1 EFI SHA256: " + result["loaderSha256"], "",
        "Ghidra static pseudocode only. Neither the exact runtime physical base "
        "nor a final Linux handoff has yet been verified.", "",
        "## Symbolic relationships", "",
        "- Firmware variables: KernelBaseAddr / KernelSize if queries succeed",
        "- ARM64 bias: 0x80000; alternate image bias: 0x8000",
        "- Fallback: (BaseMemory | OEM_OFFSET)",
        "- Post-selection KASLR displacement: DAT_0032a4c8 << 15",
        "- Computed local_190 is kernel load destination; local_180 ramdisk;",
        "  local_178 is device-tree destination", "",
        "## Exact observed placement expressions", "",
    ]
    for name, info in result["placementStatements"].items():
        items += [name + " | present: " + str(info["observed"]),
                  "line: " + str(info["line"]), ""]
        if info["observed"]:
            items += ["~~~c", *info["excerpt"], "~~~", ""]
    items += ["## Device-tree selector properties", ""]
    for name, info in result["dtbProperties"].items():
        items += [name + " | present: " + str(info["observed"])]
    items += ["", "## Ghidra HighFunction p-code metadata", "",
              "~~~json", json.dumps(result["highFunctionMetadata"], indent=2), "~~~", "",
              "## Previously omitted BootLinux pseudocode tail", "",
              "This is the last 180 lines of the ORIGINAL Ghidra decompiler output,",
              "not the truncated 18,000-character preview from the earlier audit.", "",
              "~~~c", *result["bootLinuxTail"], "~~~", "",
              "## Still unknown", "",
              "Runtime firmware-variable values or OEM fallback offsets; KASLR value;",
              "actual branch taken; execution handoff entrypoint and register values.",
              "This report must not be used to invent a kernel_phys_load value.", ""]
    return "\n".join(items)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path.home() /
                   "s20-artifacts/hxl1-research/abl-linuxloader")
    args = p.parse_args()
    try:
        result = trace(args.out)
        (args.out / "rea-stage4-placement-tail.json").write_text(
            json.dumps(result, indent=2) + "\n")
        (args.out / "rea-stage4-placement-tail.md").write_text(render(result))
    except (OSError, AuditError, ValueError, KeyError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2
    for key, item in result["placementStatements"].items():
        print("[OBSERVED]" if item["observed"] else "[MISSING]", key)
    print("[BOOTLINUX LINES]", result["bootLinuxTotalLines"])
    print("[HIGHFUNCTION]", result["highFunctionMetadata"].get("available"))
    print("[REPORT]", args.out / "rea-stage4-placement-tail.md")
    print("[LIMIT] Numerical runtime physical kernel load/handoff still unverified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
