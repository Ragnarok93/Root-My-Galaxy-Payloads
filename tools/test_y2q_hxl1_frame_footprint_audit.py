"""Offline tests for recorded HXL1 AArch64 entry stack adjustments."""
from pathlib import Path
import io
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_frame_footprint_audit as m


class FrameFootprintTests(unittest.TestCase):
    def test_parse_original_binutils_style(self):
        data = (b"0000000000001000: d10703ff sub sp, sp, #0x1c0\n"
                b"0000000000001004: 910703ff add sp, sp, #0x1c0\n")
        self.assertEqual(m.parse_instructions(data),
                         [(0x1000, "sub", "sp, sp, #0x1c0"),
                          (0x1004, "add", "sp, sp, #0x1c0")])

    def test_simple_entry_stack_footprint(self):
        rows = [(0x1000, "sub", "sp, sp, #0x1e0"),
                (0x1004, "add", "sp, sp, #0x1e0")]
        data = m.frame(rows)
        self.assertEqual(data["staticEntryBytes"], 480)
        self.assertTrue(data["literalRestorationsBalanceEntry"])
        self.assertFalse(data["sourceLocalVariablesIdentified"])

    def test_preindexed_stack_save_and_restore(self):
        rows = [(0x1000, "stp", "x29, x16, [sp, #-96]!"),
                (0x1004, "sub", "sp, sp, #0x310"),
                (0x1008, "add", "sp, sp, #0x310"),
                (0x100c, "ldp", "x29, x16, [sp], #96")]
        self.assertEqual(m.frame(rows)["staticEntryBytes"], 880)

    def test_late_stack_allocation_is_not_counted_as_simple_footprint(self):
        rows = [(0x1000, "sub", "sp, sp, #0x100"),
                (0x1200, "sub", "sp, sp, #0x20"),
                (0x1204, "add", "sp, sp, #0x120")]
        data = m.frame(rows)
        self.assertIsNone(data["staticEntryBytes"])
        self.assertFalse(data["allRuntimePathsCertified"])

    def test_unbalanced_restoration_remains_unknown(self):
        data = m.frame([(0x1000, "sub", "sp, sp, #0x100"),
                        (0x1004, "add", "sp, sp, #0x80")])
        self.assertIsNone(data["staticEntryBytes"])

    def test_empty_instruction_window_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing original"):
            m.frame([])

    def test_report_never_promotes_runtime_or_source_local_proof(self):
        rec = m.frame([(0x1000, "sub", "sp, sp, #0x120"),
                       (0x1004, "add", "sp, sp, #0x120")])
        self.assertFalse(rec["allRuntimePathsCertified"])
        self.assertFalse(rec["sourceLocalVariablesIdentified"])

    def test_unsafe_archive_is_rejected_by_prerequisite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tar.gz"
            with tarfile.open(path, "w:gz") as tar:
                header = tarfile.TarInfo("unsafe")
                body = b"bad"
                header.size = len(body)
                tar.addfile(header, io.BytesIO(body))
            with self.assertRaises((ValueError, KeyError)):
                m.audit(path)


if __name__ == "__main__":
    unittest.main()
