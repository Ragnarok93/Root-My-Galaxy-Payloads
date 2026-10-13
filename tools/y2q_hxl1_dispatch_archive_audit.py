#!/usr/bin/env python3
"""Reconcile SHA-verified archived HXL1 futex dispatch, without device access.

This checks historical machine-code evidence only. It does not establish
source-level helper inlining, live addresses, stack geometry or privileges.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

EXPECTED = ("core_sys_select", "do_select", "futex_requeue",
            "do_futex", "futex_lock_pi")
LINE = re.compile(r"^([0-9a-f]{16}):\s+[0-9a-f]{8}\s+(\S+)\s*(.*?)\s*$", re.I)
MAX_ARCHIVE = 4_000_000
MAX_TEXT = 500_000


class AuditError(ValueError):
    pass


def require(ok: bool, explanation: str) -> None:
    if not ok:
        raise AuditError(explanation)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink()
            and path.stat().st_size <= MAX_ARCHIVE,
            "Archive missing or oversized")
    with tarfile.open(path, "r:gz") as ar:
        members = ar.getmembers()
        require({m.name for m in members} ==
                {"stack-gate.json"} | {x + ".disasm.txt" for x in EXPECTED}
                and all(m.isfile() and m.size <= MAX_TEXT for m in members),
                "Unexpected archive member, type, or size")
        manifest = json.loads(ar.extractfile("stack-gate.json").read())
        require(manifest.get("target") == "SM-G986U1/G986U1UESCHXL1"
                and manifest.get("originalKernelSha256Verified") is True
                and manifest.get("originalFunctionsWithBoundedCode") == 5,
                "Manifest is not the expected HXL1 five-window inventory")
        reports = {x["symbol"]: x for x in manifest["functions"]}
        require(reports["futex_wait_requeue_pi"]["status"] ==
                "NOT_FOUND_IN_RECOVERED_NM",
                "Missing-function label changed")
        extracted = {}
        count = 0
        for name in EXPECTED:
            record = reports[name]
            body = ar.extractfile(name + ".disasm.txt").read()
            require(sha(body) == record["disassembly"]["textSha256"],
                    "Archived disassembly SHA256 mismatch: " + name)
            start = int(record["recoveredFileRelativeImageVA"], 16)
            count_expected = record["byteCount"] // 4
            rows = []
            for line in body.decode("utf-8").splitlines():
                match = LINE.match(line)
                if match:
                    rows.append((int(match.group(1), 16), match.group(2),
                                 match.group(3).split("//")[0].strip()))
            require(len(rows) == count_expected and
                    all(row[0] == start + 4 * i
                        for i, row in enumerate(rows)),
                    "Disassembly address continuity failed: " + name)
            extracted[name] = (start, rows)
            count += len(rows)

    commands = {address:(op, val) for address, op, val in extracted["do_futex"][1]}
    landmarks = {
        "opcode_11_comparison": (0xffffff800818f040, "cmp", "w8, #0xb"),
        "opcode_11_branch": (0xffffff800818f044, "b.eq", "0xffffff800818f0fc"),
        "opcode_12_comparison": (0xffffff800818f048, "cmp", "w8, #0xc"),
        "opcode_12_requeue_call": (0xffffff800818f06c, "bl",
                                   hex(extracted["futex_requeue"][0])),
        "opcode_11_internal_entry": (0xffffff800818f0fc, "adrp", "x8, "),
    }
    for label, (addr, op, val) in landmarks.items():
        got = commands.get(addr, ("MISSING", ""))
        require(got[0] == op and got[1].startswith(val),
                "Original HXL1 dispatch landmark mismatch: " + label)

    return {
        "schemaVersion": 1,
        "target": "SM-G986U1/G986U1UESCHXL1",
        "archiveSha256": sha(path.read_bytes()),
        "matchedArchivedDisassemblySha256": len(EXPECTED),
        "instructionSlotsAccountedFor": count,
        "opcode11InternalDispatchRecognized": True,
        "opcode12NamedRequeueDispatchRecognized": True,
        "missingHelperNameCannotProveFunctionAbsence": True,
        "exactSourceHelperInliningProven": False,
        "crossFunctionStackLayoutProven": False,
        "originalKernelImageIndependentlyRehashed": False,
        "runtimeKernelOrRootVerified": False,
        "phoneModified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path,
                        help="Existing original HXL1 disassembly-review.tar.gz")
    parser.add_argument("--out", type=Path)
    opts = parser.parse_args()
    try:
        report = audit(opts.archive)
        if opts.out:
            require(not opts.out.exists(), "Refuse to overwrite prior evidence")
            opts.out.write_text(json.dumps(report, indent=2) + "\n")
        print("[ARCHIVED DISASSEMBLY HASHES]", report["matchedArchivedDisassemblySha256"])
        print("[DISPATCH OPERATIONS 11/12] CODE PATHS FOUND")
        print("[SOURCE HELPER INLINE STATUS] UNVERIFIED")
        print("[ROOT] UNVERIFIED")
        return 0
    except (AuditError, OSError, ValueError, KeyError, TypeError,
            tarfile.TarError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
