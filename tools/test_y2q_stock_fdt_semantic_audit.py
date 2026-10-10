#!/usr/bin/env python3
"""Offline tests for semantic FDT token parsing of original HXL1 boot image."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import y2q_stock_fdt_semantic_audit as mod
from tools.test_y2q_stock_dtb_inventory import fake_boot, fake_fdt


def fdt_with_compat() -> bytes:
    strings = b"compatible\0model\0"
    values = (("compatible", b"qcom,kona\0samsung,y2q\0", 0),
              ("model", b"Samsung Galaxy S20+\0", 11))
    structure = bytearray(b"\0\0\0\1" + b"\0" * 4)
    for _name, val, offset in values:
        structure += struct.pack(">III", 3, len(val), offset)
        structure += val
        structure += b"\0" * ((-len(val)) % 4)
    structure += struct.pack(">II", 2, 9)
    off_struct = 56
    off_strings = off_struct + len(structure)
    header = struct.pack(
        ">10I", 0xD00DFEED, off_strings + len(strings),
        off_struct, off_strings, 40, 17, 16, 0, len(strings),
        len(structure))
    return header + b"\0" * 16 + structure + strings


class SemanticFdtTests(unittest.TestCase):
    def test_parse_minimal_header_valid_tree(self):
        r = mod.validate_fdt_tree(fake_fdt())
        self.assertEqual(r["nodeCount"], 1)
        self.assertEqual(r["propertyCount"], 0)
        self.assertEqual(r["fullStructureTokenValidation"], "PASS")
        self.assertFalse(r["selectedRuntimeDtbProved"])

    def test_parse_root_compatible_and_model_values(self):
        r = mod.validate_fdt_tree(fdt_with_compat())
        self.assertEqual(r["rootCompatible"], ["qcom,kona", "samsung,y2q"])
        self.assertEqual(r["rootModel"], ["Samsung Galaxy S20+"])
        self.assertEqual(r["propertyCount"], 2)

    def test_root_compatible_can_be_missing_without_false_claim(self):
        r = mod.validate_fdt_tree(fake_fdt())
        self.assertFalse(r["rootCompatiblePropertyPresent"])
        self.assertEqual(r["rootCompatible"], [])

    def test_invalid_property_name_offset_fails(self):
        b = bytearray(fdt_with_compat())
        # Structure: root BEGIN_NODE at 56, name at 60, first PROP at 64,
        # length at 68, nameoff at 72.
        struct.pack_into(">I", b, 72, 0xFFFFFFF0)
        with self.assertRaisesRegex(mod.AuditError, "property name offset"):
            mod.validate_fdt_tree(bytes(b))

    def test_unmatched_end_node_fails(self):
        b = bytearray(fake_fdt())
        # FDT token structure begins at 56; change root START to END_NODE.
        struct.pack_into(">I", b, 56, 2)
        self.assertIsNone(mod.check_fdt_header(bytes(b), 0))

    def test_missing_fdt_end_token_is_rejected(self):
        b = bytearray(fake_fdt())
        struct.pack_into(">I", b, 68, 4)
        with self.assertRaisesRegex(mod.AuditError, "header"):
            mod.validate_fdt_tree(bytes(b))

    def test_ascii_property_string_decoder_is_bounded(self):
        self.assertEqual(mod.string_list(b"qcom,kona\0samsung,y2q\0"),
                         ["qcom,kona", "samsung,y2q"])
        self.assertEqual(mod.string_list(b"\xff\0"), [])
        self.assertEqual(mod.string_list(b"\0"), [])
        self.assertEqual(mod.string_list(b"A" * 4097 + b"\0"), [])

    def test_multiple_contiguous_trees_and_hash_pins(self):
        first, second = fdt_with_compat(), fake_fdt()
        embedded = first + second
        boot = fake_boot(embedded)
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                "dtb.img": hashlib.sha256(embedded).hexdigest()}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            with (mock.patch.object(mod, "PINS", pins),
                  mock.patch.object(mod, "EXPECTED_BOOT_FILE_SIZE", len(boot))):
                result = mod.audit(root)
        self.assertTrue(result["allFdtStructuresPass"])
        self.assertTrue(result["contiguousCompleteRegionCoverage"])
        self.assertEqual(result["fdtHeaderCandidates"], 2)
        self.assertEqual(result["candidates"][0]["rootCompatible"],
                         ["qcom,kona", "samsung,y2q"])
        self.assertFalse(result["exactRuntimeSelectedDtbVerified"])
        self.assertFalse(result["physicalKernelLoadAddressVerified"])
        self.assertFalse(result["phoneModified"])

    def test_embedded_original_dtb_digest_failure_is_rejected(self):
        dtb = fake_fdt()
        boot = fake_boot(dtb)
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(), "dtb.img": "0"*64}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            with (mock.patch.object(mod, "PINS", pins),
                  mock.patch.object(mod, "EXPECTED_BOOT_FILE_SIZE", len(boot))):
                with self.assertRaisesRegex(mod.AuditError, "embedded DTB SHA256"):
                    mod.audit(root)

    def test_tool_exposes_no_device_or_exploit_actions(self):
        source = Path(mod.__file__).read_text()
        for prohibited in ("fastboot flash", "adb shell", "KernelSU",
                           "FUTEX_CMP_REQUEUE_PI", "setresuid(0)"):
            self.assertNotIn(prohibited, source)
        self.assertIn('"physicalKernelLoadAddressVerified": False', source)


if __name__ == "__main__":
    unittest.main()
