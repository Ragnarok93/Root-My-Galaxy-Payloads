"""Synthetic tests for HXL1 read-only select header/source provenance."""
import hashlib
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


if __name__ == "__main__":
    unittest.main()
