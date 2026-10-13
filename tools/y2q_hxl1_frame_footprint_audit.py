#!/usr/bin/env python3
"""Read-only ARM64 frame-entry observations from verified HXL1 disassembly."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys
import tarfile
from tools import y2q_hxl1_dispatch_archive_audit as prior

INSN = re.compile(r"^([0-9a-f]{16}):\s+[0-9a-f]{8}\s+(\S+)(?:\s+(.*?))?\s*$", re.I)
IMM = re.compile(r"^sp,\s*sp,\s*#(0x[0-9a-f]+|\d+)$", re.I)
PRE = re.compile(r"\[sp,\s*#-(0x[0-9a-f]+|\d+)\]!", re.I)
POST = re.compile(r"\[sp\],\s*#(0x[0-9a-f]+|\d+)", re.I)
FUNCTIONS = ("core_sys_select", "do_select", "do_futex",
             "futex_requeue", "futex_lock_pi")

def parse_instructions(raw: bytes) -> list[tuple[int,str,str]]:
    rows = []
    for line in raw.decode("utf-8").splitlines():
        match = INSN.match(line)
        if match:
            va, opcode, ops = match.groups()
            rows.append((int(va, 16), opcode.lower(),
                         (ops or "").split("//")[0].strip()))
    return rows

def frame(rows: list[tuple[int,str,str]]) -> dict:
    if not rows:
        raise ValueError("Missing original instructions")
    entry, late, restore = [], [], []
    for addr, op, args in rows:
        direction, match = None, None
        if op in ("sub", "add") and (match := IMM.fullmatch(args)):
            direction = "alloc" if op == "sub" else "restore"
        elif op == "stp" and (match := PRE.search(args)):
            direction = "alloc"
        elif op == "ldp" and (match := POST.search(args)):
            direction = "restore"
        if match:
            entry_record = {"address": hex(addr), "bytes": int(match.group(1), 0),
                            "instruction": op + " " + args}
            if direction == "restore":
                restore.append(entry_record)
            elif addr - rows[0][0] < 128:
                entry.append(entry_record)
            else:
                late.append(entry_record)
    footprint = sum(x["bytes"] for x in entry)
    balanced = (bool(entry) and not late and
                footprint == sum(x["bytes"] for x in restore))
    return {"entryStackAdjustments": entry,
            "restorationAdjustments": restore,
            "laterAdjustments": late,
            "staticEntryBytes": footprint if balanced else None,
            "literalRestorationsBalanceEntry": balanced,
            "allRuntimePathsCertified": False,
            "sourceLocalVariablesIdentified": False}

def audit(path: Path) -> dict:
    # Reuse existing strict archive/manifest/hash and operation-11 checks.
    verified = prior.audit(path)
    with tarfile.open(path, "r:gz") as archive:
        frames = {}
        for function in FUNCTIONS:
            item = archive.getmember(function + ".disasm.txt")
            raw = archive.extractfile(item).read()
            rows = parse_instructions(raw)
            if not rows:
                raise ValueError("Missing disassembly: " + function)
            frames[function] = frame(rows)
    return {"target": verified["target"],
            "archiveSha256": verified["archiveSha256"],
            "archivedInstructionSlotsChecked": verified["instructionSlotsAccountedFor"],
            "disassemblySha256sVerified": verified["matchedArchivedDisassemblySha256"],
            "entryFrameFootprints": frames,
            "compiledOperation11BranchPresent": verified["opcode11InternalDispatchRecognized"],
            "sourceHelperInliningCertified": False,
            "crossSyscallStackRelationshipCertified": False,
            "runtimeRootOrKernelSuCertified": False,
            "originalImageByteComparisonIndependentlyDone": False}

def markdown(report: dict) -> str:
    lines = ["# HXL1 original AArch64 entry-frame audit", "",
             "Read-only static observations; not proof of runtime stack-object reuse.",
             "", "| Function | Entry-frame allocation | Restoration observed |",
             "| --- | ---: | --- |"]
    for name, rec in report["entryFrameFootprints"].items():
        value = rec["staticEntryBytes"]
        lines.append("| {} | {} | {} |".format(
            name, str(value) + " bytes" if value is not None else "UNKNOWN",
            "YES" if rec["literalRestorationsBalanceEntry"] else "UNKNOWN"))
    lines += ["", "Source helper inlining: NOT CERTIFIED",
              "Cross-syscall stack relationship: NOT CERTIFIED",
              "Temporary root and KernelSU: NOT CERTIFIED", ""]
    return "\n".join(lines)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output-dir", type=Path)
    opts = parser.parse_args()
    try:
        result = audit(opts.archive)
        if opts.output_dir:
            if opts.output_dir.exists():
                raise ValueError("Output directory must be new")
            opts.output_dir.mkdir(parents=True, exist_ok=False)
            (opts.output_dir/"frame-footprint.json").write_text(
                json.dumps(result, indent=2) + "\n")
            (opts.output_dir/"frame-footprint.md").write_text(markdown(result))
        print("[VERIFIED DISASSEMBLIES]", result["disassemblySha256sVerified"])
        for name, rec in result["entryFrameFootprints"].items():
            print("[STATIC ENTRY]", name, rec["staticEntryBytes"])
        print("[STACK RELATIONSHIP/ROOT CERTIFIED] NO")
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
