#!/usr/bin/env python3
"""Offline unit tests for hash-pinned HXL1 bootloader ELF classification."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("y2q_stock_bl_elf_audit.py")
spec = importlib.util.spec_from_file_location("y2q_stock_bl_elf_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
spec.loader.exec_module(audit)


def make_elf(bits: int, machine: int, entry: int,
             virt: int, phys: int, flags: int = 5) -> bytes:
    header_len = 52 if bits == 32 else 64
    ph_len = 32 if bits == 32 else 56
    blob = bytearray(0x200)
    blob[:7] = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1, 1])
    struct.pack_into("<HHI", blob, 16, 2, machine, 1)
    if bits == 32:
        struct.pack_into("<II", blob, 24, entry, header_len)
        struct.pack_into("<HHH", blob, 40, header_len, ph_len, 1)
        struct.pack_into("<IIIIIIII", blob, header_len,
                         1, 0x100, virt, phys, 32, 48, flags, 0x1000)
    else:
        struct.pack_into("<QQ", blob, 24, entry, header_len)
        struct.pack_into("<HHH", blob, 52, header_len, ph_len, 1)
        struct.pack_into("<IIQQQQQQ", blob, header_len,
                         1, flags, 0x100, virt, phys, 32, 48, 0x1000)
    return bytes(blob)


class BootloaderAuditTests(unittest.TestCase):
    def test_arm32_abl_entry_inside_executable_load(self):
        image = make_elf(32, 40, 0x9FA00000, 0x9FA00000, 0x9FA00000)
        r = audit.parse_elf(image)
        self.assertEqual(r["elfClass"], "ELF32")
        self.assertEqual(r["machine"], 40)
        self.assertEqual(r["entryPoint"], 0x9FA00000)
        self.assertTrue(r["entryInExecutableLoadSegment"])

    def test_aarch64_xbl_entry_inside_executable_load(self):
        image = make_elf(64, 183, 0x148157A8, 0x148157A0, 0x148157A0)
        r = audit.parse_elf(image)
        self.assertEqual(r["elfClass"], "ELF64")
        self.assertEqual(r["machine"], 183)
        self.assertTrue(r["entryInExecutableLoadSegment"])

    def test_elf64_arm_config_is_classified_not_mislabelled_aarch64(self):
        image = make_elf(64, 40, 0x148D0000, 0x148D0000, 0x148D0000)
        r = audit.parse_elf(image)
        self.assertEqual(r["elfClass"], "ELF64")
        self.assertEqual(r["machine"], 40)

    def test_entry_in_nonexecutable_segment_does_not_pass(self):
        image = make_elf(32, 40, 0x2000, 0x2000, 0x2000, flags=4)
        self.assertFalse(audit.parse_elf(image)["entryInExecutableLoadSegment"])

    def test_corrupted_load_file_bounds_fail_closed(self):
        b = bytearray(make_elf(32, 40, 0x2000, 0x2000, 0x2000))
        struct.pack_into("<I", b, 52 + 4, 0xFFFFFFF0)
        with self.assertRaisesRegex(audit.AuditError, "invalid file or memory size"):
            audit.parse_elf(bytes(b))

    def test_bad_header_count_rejected(self):
        b = bytearray(make_elf(64, 183, 0x1000, 0x1000, 0x1000))
        struct.pack_into("<H", b, 56, 0xFFFF)
        with self.assertRaisesRegex(audit.AuditError, "extends beyond file"):
            audit.parse_elf(bytes(b))

    def test_cross_image_overlap_does_not_imply_kernel_handoff(self):
        a = audit.parse_elf(make_elf(32, 40, 0x9FA00000,
                                     0x9FA00000, 0x9FA00000))
        b = audit.parse_elf(make_elf(64, 183, 0x9FA00020,
                                     0x9FA00020, 0x9FA00020))
        overlaps = audit.overlap_ranges(a, b)
        self.assertEqual(len(overlaps), 1)
        self.assertEqual(overlaps[0]["overlapBytes"], 16)
        self.assertIn("not kernel handoff", overlaps[0]["note"])

    def test_exact_hash_pins_and_anomaly_warning(self):
        data = {
            "abl.elf": make_elf(32, 40, 0x9FA00000, 0x9FA00000, 0x9FA00000),
            "xbl.elf": make_elf(64, 183, 0x148157A8, 0x148157A8, 0x148157A8),
            "xbl_config.elf": make_elf(64, 40, 0x148D0000, 0x148D0000, 0x148D0000),
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            expected = {}
            for name, blob in data.items():
                (root / name).write_bytes(blob)
                expected[name] = {
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "class": 1 if name == "abl.elf" else 2,
                    "machine": 183 if name == "xbl.elf" else 40,
                    "entry": {
                        "abl.elf": 0x9FA00000,
                        "xbl.elf": 0x148157A8,
                        "xbl_config.elf": 0x148D0000,
                    }[name],
                    "programHeaders": 1,
                }
            with mock.patch.object(audit, "INPUTS", expected):
                result = audit.audit(root)
            self.assertTrue(result["xblConfigHasUnusualElfClassMachineCombination"])
            self.assertFalse(result["runtimeLinuxKernelPhysicalBaseVerified"])
            self.assertFalse(result["linuxHandoffRegistersVerified"])
            self.assertFalse(result["phoneModified"])
            self.assertIn("not established", audit.report_markdown(result))

    def test_fails_if_pinned_original_image_is_modified(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "abl.elf").write_bytes(b"forged input")
            with self.assertRaisesRegex(audit.AuditError, "SHA256 mismatch"):
                audit.audit(root)

    def test_no_device_actions(self):
        source = SCRIPT.read_text()
        for forbidden in ("adb shell", "fastboot flash", "os.system(", "subprocess.run(",
                          "FUTEX_CMP_REQUEUE_PI", "setresuid(0)"):
            self.assertNotIn(forbidden, source)
        self.assertIn('"phoneModified": False', source)
        self.assertIn('"runtimeLinuxKernelPhysicalBaseVerified": False', source)


if __name__ == "__main__":
    unittest.main()
