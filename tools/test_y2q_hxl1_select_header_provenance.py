"""Synthetic tests for HXL1 read-only select header/source provenance."""
import hashlib
import io
import json
import tarfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_select_header_provenance as m


SOURCE = b"#include <linux/poll.h>\nlong stack_fds[SELECT_STACK_ALLOC/sizeof(long)];\n"
FUTEX = b"original Samsung futex source stand-in"


def fixture(root: Path, header: bytes) -> None:
    for name, content in ((m.HEADER, header),
                          ("fs/select.c", SOURCE), ("kernel/futex.c", FUTEX)):
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)


def pins():
    return {"fs/select.c": hashlib.sha256(SOURCE).hexdigest(),
            "kernel/futex.c": hashlib.sha256(FUTEX).hexdigest()}


class HeaderProvenanceTests(unittest.TestCase):
    def test_simple_original_style_alias_chain(self):
        source = ("#define FRONTEND_STACK_ALLOC 256\n"
                  "#define SELECT_STACK_ALLOC FRONTEND_STACK_ALLOC\n")
        value, chain = m.resolve(m.definitions(source), "SELECT_STACK_ALLOC")
        self.assertEqual(value, 256)
        self.assertEqual(chain, ["SELECT_STACK_ALLOC=FRONTEND_STACK_ALLOC",
                                 "FRONTEND_STACK_ALLOC=256"])

    def test_unrelated_conditional_macro_definitions_allowed(self):
        header = ("#ifdef __clang__\n#define MAX_STACK_ALLOC 768\n"
                  "#else\n#define MAX_STACK_ALLOC 832\n#endif\n"
                  "#define FRONTEND_STACK_ALLOC 256\n"
                  "#define SELECT_STACK_ALLOC FRONTEND_STACK_ALLOC\n")
        self.assertEqual(m.resolve(m.definitions(header),
                                   "SELECT_STACK_ALLOC")[0], 256)

    def test_ambiguous_macro_inside_alias_chain_rejected(self):
        body = ("#define FRONTEND_STACK_ALLOC 256\n"
                "#define FRONTEND_STACK_ALLOC 512\n"
                "#define SELECT_STACK_ALLOC FRONTEND_STACK_ALLOC\n")
        with self.assertRaisesRegex(m.SourceError, "Ambiguous conditional"):
            m.resolve(m.definitions(body), "SELECT_STACK_ALLOC")

    def test_alias_cycles_rejected(self):
        with self.assertRaisesRegex(m.SourceError, "cycle"):
            m.resolve(m.definitions(
                "#define SELECT_STACK_ALLOC X\n#define X SELECT_STACK_ALLOC\n"),
                "SELECT_STACK_ALLOC")

    def test_complex_expression_is_not_guessed(self):
        with self.assertRaisesRegex(m.SourceError, "Complex macro"):
            m.resolve(m.definitions(
                "#define SELECT_STACK_ALLOC (128 + 128)\n"),
                "SELECT_STACK_ALLOC")

    def test_sibling_source_pins_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root, b"#define SELECT_STACK_ALLOC 256\n")
            with self.assertRaisesRegex(m.SourceError, "pin mismatch"):
                m.audit(root)

    def test_correct_sibling_pins_and_header_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root, (b"#define FRONTEND_STACK_ALLOC 256\n"
                           b"#define SELECT_STACK_ALLOC FRONTEND_STACK_ALLOC\n"))
            with patch.object(m, "SOURCE_PINS", pins()):
                report = m.audit(root)
        self.assertEqual(report["selectStackAllocationSourceBytes"], 256)
        self.assertTrue(report["sourceHeaderAndPinnedSourceAgree"])
        self.assertFalse(report["oemCompiledStackLocalOffsetProven"])
        self.assertFalse(report["runtimeStackReuseOrPrivilegeProven"])
        self.assertFalse(report["deviceAccessed"])

    def test_header_symlink_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root, b"#define SELECT_STACK_ALLOC 256\n")
            header = root / m.HEADER
            header.unlink()
            header.symlink_to(root / "fs/select.c")
            with patch.object(m, "SOURCE_PINS", pins()):
                with self.assertRaisesRegex(m.SourceError, "unsafe"):
                    m.audit(root)

    def test_missing_exact_poll_include_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root, b"#define SELECT_STACK_ALLOC 256\n")
            (root / "fs/select.c").write_bytes(
                SOURCE.replace(b"#include <linux/poll.h>", b""))
            with patch.object(m, "SOURCE_PINS",
                              {"fs/select.c": hashlib.sha256(
                                  SOURCE.replace(b"#include <linux/poll.h>", b"")).hexdigest(),
                               "kernel/futex.c": hashlib.sha256(FUTEX).hexdigest()}):
                with self.assertRaisesRegex(m.SourceError, "does not include"):
                    m.audit(root)


    def test_saved_native_disassembly_verified_with_existing_manifest(self):
        code = (b"ffffff80082f8e10: 910143f3 add x19, sp, #0x50\n"
                b"ffffff80082f8dd8: f106011f cmp x8, #0x180\n")
        manifest = {"functions": [{
            "symbol": "core_sys_select",
            "disassembly": {"textSha256": hashlib.sha256(code).hexdigest()}
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old-evidence.tar.gz"
            with tarfile.open(path, "w:gz") as tar:
                for name, body in (
                    ("stack-gate.json", json.dumps(manifest).encode()),
                    ("core_sys_select.disasm.txt", code)):
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    tar.addfile(member, io.BytesIO(body))
            with patch("tools.y2q_hxl1_dispatch_archive_audit.audit",
                       return_value={"matchedArchivedDisassemblySha256": 5}):
                result = m.check_saved_disassembly(path)
        self.assertTrue(result["nativeSelectStackPathRecognized"])
        self.assertTrue(result["nativeSelectDynamicChoiceRecognized"])
        self.assertFalse(result["sourceMacroToExactMachineObjectCertified"])

    def test_altered_native_disassembly_manifest_hash_rejected(self):
        original = b"ffffff80082f8e10: 910143f3 add x19, sp, #0x50\n"
        manifest = {"functions": [{
            "symbol": "core_sys_select",
            "disassembly": {"textSha256": hashlib.sha256(original).hexdigest()}
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered.tar.gz"
            with tarfile.open(path, "w:gz") as tar:
                for name, body in (
                    ("stack-gate.json", json.dumps(manifest).encode()),
                    ("core_sys_select.disasm.txt", original + b"tampered")):
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    tar.addfile(member, io.BytesIO(body))
            with patch("tools.y2q_hxl1_dispatch_archive_audit.audit",
                       return_value={"matchedArchivedDisassemblySha256": 5}):
                with self.assertRaisesRegex(m.SourceError, "hash mismatch"):
                    m.check_saved_disassembly(path)



    @staticmethod
    def _compiled_threshold_fixture() -> str:
        # Equivalent arithmetic and branch form, not an exploit payload.
        start = 0x1000
        rows = [
            ("sxtw", "x8, w22"),
            ("add", "x8, x8, #0x3f"),
            ("lsr", "x27, x8, #6"),
            ("cmp", "x8, #0x180"),
            ("b.cc", "0x1100"),
            ("mov", "w1, #0xc0"),
            ("add", "x8, x27, x27, lsl #1"),
            ("movk", "w1, #0x60, lsl #16"),
            ("mov", "w2, #0xffffffff"),
            ("lsl", "x0, x8, #4"),
        ]
        result = [f"{start+4*i:016x}: d503201f {mn} {ops}"
                  for i, (mn, ops) in enumerate(rows)]
        result.append(f"{0x1100:016x}: d503201f add x19, sp, #0x50")
        return "\n".join(result) + "\n"

    def test_compiled_select_cutoff_corresponds_to_256_byte_source(self):
        report = m.numeric_select_crosswalk(
            self._compiled_threshold_fixture(), 256)
        self.assertEqual(report["maximumNfdsUsingStack"], 320)
        self.assertEqual(report["firstNfdsRequiringDynamicAllocation"], 321)
        self.assertEqual(report["dynamicAllocationBytesPer64Descriptors"], 48)
        self.assertEqual(report["roundedCountComparisonOperand"], 384)
        self.assertEqual(report["smallestSourceArrayBytesWithThisCompiledCutoff"], 240)
        self.assertEqual(report["largestSourceArrayBytesWithThisCompiledCutoff"], 287)
        self.assertFalse(report["compiledCutoffUniquelyAuthenticatesExactSourceBytes"])
        self.assertFalse(report["crossSyscallReuseOrRootCertified"])

    def test_wrong_compiled_comparison_or_wrong_header_capacity_rejected(self):
        body = self._compiled_threshold_fixture()
        with self.assertRaisesRegex(m.SourceError, "disagrees"):
            m.numeric_select_crosswalk(body.replace("#0x180", "#0x1c0"), 256)
        with self.assertRaisesRegex(m.SourceError, "disagrees"):
            m.numeric_select_crosswalk(body, 512)

    def test_branch_must_target_the_stack_backed_path(self):
        body = self._compiled_threshold_fixture()
        with self.assertRaisesRegex(m.SourceError, "no longer targets"):
            m.numeric_select_crosswalk(
                body.replace("b.cc 0x1100", "b.cc 0x1200"), 256)

    def test_dynamic_alloc_sizing_must_match_six_eight_byte_words(self):
        body = self._compiled_threshold_fixture()
        with self.assertRaisesRegex(m.SourceError, "sizing path"):
            m.numeric_select_crosswalk(
                body.replace("lsl x0, x8, #4", "lsl x0, x8, #5"), 256)



if __name__ == "__main__":
    unittest.main()
