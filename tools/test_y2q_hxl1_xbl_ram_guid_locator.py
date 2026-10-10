#!/usr/bin/env python3
"""Offline fixtures for SHA-pinned exact GUID lookup in original XBL ELFs."""
from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_xbl_ram_guid_locator as mod


def elf_image(*, guid_offset=0x170, guid=mod.GUID_LE, loaded=True):
    """Minimal synthetic ELF64 LE AArch64 with one file-backed PT_LOAD."""
    blob = bytearray(0x380)
    blob[:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    struct.pack_into("<HHIQQQIHHHHHH", blob, 16,
                     2, 183, 1, 0x1010, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", blob, 64,
                     1, 5, 0x100, 0x1000, 0x85000000,
                     0x100 if loaded else 0x40, 0x100, 0x1000)
    blob[guid_offset:guid_offset+len(guid)] = guid
    return bytes(blob)


def expectation(data):
    return {
        "sha256": mod.sha256(data),
        "class": 2, "machine": 183,
        "entry": 0x1010, "programHeaders": 1,
    }


class ExactOriginalGuidTests(unittest.TestCase):
    def test_little_endian_guid_inside_load(self):
        data = elf_image()
        result = mod.locate(data, expectation(data))
        self.assertEqual(result["matchCount"], 1)
        hit = result["matches"][0]
        self.assertEqual(hit["representation"], "UEFI_GUID_LITTLE_ENDIAN")
        self.assertEqual(hit["fileOffset"], "0x170")
        self.assertTrue(hit["withinFileBackedLoadSegment"])
        self.assertEqual(hit["loadSegmentLocations"][0]["elfSegmentVirtualAddress"],
                         hex(0x1070))
        self.assertFalse(result["actualRamPartitionEntriesMeasured"])
        self.assertFalse(result["runtimePhysicalKernelEntryVerified"])

    def test_guid_outside_file_backed_load_is_not_mapped(self):
        data = elf_image(loaded=False)
        result = mod.locate(data, expectation(data))
        self.assertEqual(result["matchCount"], 1)
        self.assertFalse(result["matches"][0]["withinFileBackedLoadSegment"])

    def test_canonical_guid_does_not_become_uefi_representation(self):
        data = elf_image(guid=mod.GUID_BE)
        result = mod.locate(data, expectation(data))
        self.assertEqual(result["matchCount"], 1)
        self.assertEqual(result["matches"][0]["representation"],
                         "GUID_CANONICAL_BYTES")

    def test_absent_guid_does_not_prove_absent_provider(self):
        data = elf_image(guid=b"A"*16)
        result = mod.locate(data, expectation(data))
        self.assertEqual(result["matchCount"], 0)
        self.assertFalse(result["protocolImplementationIdentified"])

    def test_exact_stock_sha_pin_required(self):
        data = elf_image()
        want = expectation(data)
        want["sha256"] = "0"*64
        with self.assertRaisesRegex(mod.LocateError, "SHA256 mismatch"):
            mod.locate(data, want)

    def test_exact_original_elf_identity_required(self):
        data = elf_image()
        for field in ("class", "machine", "entry", "programHeaders"):
            with self.subTest(field=field):
                want = expectation(data)
                want[field] = -1
                with self.assertRaisesRegex(mod.LocateError, field):
                    mod.locate(data, want)

    def test_non_elf_or_truncated_header_rejected(self):
        with self.assertRaises(ValueError):
            mod.locate(b"not an ELF", {"sha256":mod.sha256(b"not an ELF")})

    def test_occurrence_cap_prevents_unbounded_report(self):
        with self.assertRaisesRegex(mod.LocateError, "Excessive"):
            mod.matches(mod.GUID_LE*3, mod.GUID_LE, max_hits=2)

    def test_folder_never_accepts_wrong_original_xbl(self):
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            source = elf_image()
            (d/"xbl.elf").write_bytes(source)
            (d/"xbl_config.elf").write_bytes(source)
            expected = {"xbl.elf":expectation(source),
                        "xbl_config.elf":expectation(source)}
            with patch.object(mod, "INPUTS", expected):
                report = mod.analyze_folder(d)
                self.assertEqual(len(report["images"]), 2)
                self.assertFalse(report["physicalKernelLoadVerified"])
            (d/"xbl_config.elf").write_bytes(b"corrupted")
            with patch.object(mod, "INPUTS", expected):
                with self.assertRaisesRegex(mod.LocateError, "SHA256 mismatch"):
                    mod.analyze_folder(d)

    def test_symlinked_stock_input_refused(self):
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            (d/"stock").write_bytes(elf_image())
            (d/"xbl.elf").symlink_to(d/"stock")
            with self.assertRaisesRegex(mod.LocateError, "regular ELF"):
                mod.analyze_folder(d)


if __name__ == "__main__":
    unittest.main()
