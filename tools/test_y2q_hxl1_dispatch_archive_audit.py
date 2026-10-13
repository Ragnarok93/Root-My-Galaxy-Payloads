"""Synthetic regression tests for archived HXL1 instruction evidence auditing."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tools import y2q_hxl1_dispatch_archive_audit as a

BASE = 0xffffff800818e52c
ENDING = 0xffffff800818f0fc
REQUEUE = 0xffffff8008190864


def fixture(override=None):
    sources = {}
    entries = [{"symbol": "futex_wait_requeue_pi",
                "status": "NOT_FOUND_IN_RECOVERED_NM"}]
    for name in a.EXPECTED:
        start = BASE if name == "do_futex" else (
            REQUEUE if name == "futex_requeue" else 0xffffff80082f918c)
        last = ENDING if name == "do_futex" else start
        lines = []
        special = {
            0xffffff800818f040: ("cmp", "w8, #0xb"),
            0xffffff800818f044: ("b.eq", "0xffffff800818f0fc"),
            0xffffff800818f048: ("cmp", "w8, #0xc"),
            0xffffff800818f06c: ("bl", hex(REQUEUE)),
            ENDING: ("adrp", "x8, 0xffffff8009a0b000"),
        }
        for address in range(start, last + 1, 4):
            mnemonic, operands = special.get(address, ("nop", ""))
            lines.append(f"{address:016x}: d503201f {mnemonic} {operands}\n")
        body = "".join(lines).encode()
        sources[name + ".disasm.txt"] = body
        entries.append({
            "symbol": name, "byteCount": len(lines) * 4,
            "recoveredFileRelativeImageVA": hex(start),
            "disassembly": {"textSha256": a.sha(body)}
        })
    manifest = {
        "target": "SM-G986U1/G986U1UESCHXL1",
        "originalKernelSha256Verified": True,
        "originalFunctionsWithBoundedCode": 5,
        "functions": entries,
    }
    sources["stack-gate.json"] = json.dumps(manifest).encode()
    if override is not None:
        sources[override] += b"tampered"
    return sources


def archive_at(path, source):
    with tarfile.open(path, "w:gz") as tar:
        for name, body in source.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))


class Hxl1DispatchArchiveAuditTests(unittest.TestCase):
    def test_compiled_dispatch_evidence_never_claims_root(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fixture.tar.gz"
            archive_at(path, fixture())
            report = a.audit(path)
        self.assertTrue(report["opcode11InternalDispatchRecognized"])
        self.assertTrue(report["opcode12NamedRequeueDispatchRecognized"])
        self.assertFalse(report["exactSourceHelperInliningProven"])
        self.assertFalse(report["crossFunctionStackLayoutProven"])
        self.assertFalse(report["runtimeKernelOrRootVerified"])

    def test_modified_disassembly_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fixture.tar.gz"
            archive_at(path, fixture("do_futex.disasm.txt"))
            with self.assertRaisesRegex(a.AuditError,
                                        "disassembly SHA256 mismatch"):
                a.audit(path)

    def test_missing_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(a.AuditError, "missing or oversized"):
                a.audit(Path(d) / "missing.tar.gz")


if __name__ == "__main__":
    unittest.main()
