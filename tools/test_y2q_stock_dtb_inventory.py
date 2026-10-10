#!/usr/bin/env python3
"""Host-only checks for SHA-pinned original HXL1 DTB container inventory."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import y2q_stock_dtb_inventory as audit


def fake_fdt(strings: bytes = b"compatible\0") -> bytes:
    reservemap = b"\0" * 16
    nodes = (b"\0\0\0\1" + b"\0\0\0\0" +
             b"\0\0\0\2" + b"\0\0\0\11")
    header = struct.pack(">10I", 0xD00DFEED, 40 + len(reservemap) + len(nodes) + len(strings),
                         56, 72, 40, 17, 16, 0, len(strings), len(nodes))
    return header + reservemap + nodes + strings


def fake_boot(dtb: bytes) -> bytes:
    page = 4096
    out = bytearray(page * 5)
    out[:8] = b"ANDROID!"
    struct.pack_into("<10I", out, 8, 64, 0x8000, 64, 0x2000000,
                     0, 0, 0x1E00000, page, 2, 0)
    struct.pack_into("<I", out, 1644, 1660)
    struct.pack_into("<I", out, 1648, len(dtb))
    struct.pack_into("<Q", out, 1652, 0x1F00000)
    out[page:page + 64] = b"k" * 64
    out[page * 2:page * 2 + 64] = b"r" * 64
    out[page * 3:page * 3 + len(dtb)] = dtb
    return bytes(out)


class EmbeddedDtbTests(unittest.TestCase):
    def test_accepts_well_formed_flattened_tree_header(self):
        tree = fake_fdt()
        r = audit.check_fdt_header(tree, 0)
        self.assertIsNotNone(r)
        self.assertEqual(r["version"], 17)
        self.assertEqual(r["totalSize"], len(tree))
        self.assertTrue(r["headerAndBoundaryChecksPassed"])
        self.assertFalse(r["fullFdtSemanticTreeVerified"])

    def test_fdt_strings_can_start_with_property_name(self):
        r = audit.inventory_dtb_region(fake_fdt(b"compatible\0model\0"))
        self.assertEqual(r["validatedFdtV17HeaderCount"], 1)
        self.assertEqual(r["containerPrefixClass"], "FDT_MAGIC_AT_START")

    def test_qualcomm_prefix_classified_not_falsely_parsed(self):
        blob = b"QCDT" + b"\0" * 20 + fake_fdt()
        r = audit.inventory_dtb_region(blob)
        self.assertEqual(r["containerPrefixClass"], "QCDT_MAGIC")
        self.assertEqual(r["validatedFdtV17HeaderCount"], 1)
        self.assertEqual(r["fdtV17Candidates"][0]["offsetWithinDtbRegion"], 24)

    def test_two_concatenated_dtbs_are_separate(self):
        first, second = fake_fdt(), fake_fdt(b"model\0")
        r = audit.inventory_dtb_region(first + second)
        self.assertEqual(r["validatedFdtV17HeaderCount"], 2)
        self.assertEqual(r["fdtV17Candidates"][1]["offsetWithinDtbRegion"], len(first))

    def test_invalid_struct_block_rejected(self):
        b = bytearray(fake_fdt())
        struct.pack_into(">I", b, 8, 0xFFFFFF00)
        self.assertIsNone(audit.check_fdt_header(bytes(b), 0))

    def test_invalid_final_end_token_rejected(self):
        b = bytearray(fake_fdt())
        b[68:72] = b"\0\0\0\0"
        self.assertIsNone(audit.check_fdt_header(bytes(b), 0))

    def test_qcdt_with_no_flattened_tree_does_not_claim_one(self):
        r = audit.inventory_dtb_region(b"QCDT" + b"\0" * 80)
        self.assertEqual(r["validatedFdtV17HeaderCount"], 0)

    def test_hash_pinned_original_boot_embedded_region(self):
        fdt = fake_fdt()
        boot = fake_boot(fdt)
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                "dtb.img": hashlib.sha256(fdt).hexdigest()}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            with (mock.patch.object(audit, "PINS", pins),
                  mock.patch.object(audit, "EXPECTED_BOOT_FILE_SIZE", len(boot))):
                result = audit.analyze(root)
        self.assertEqual(result["dtbInventory"]["validatedFdtV17HeaderCount"], 1)
        self.assertEqual(result["bootHeaderDeclaredDtbAddr"], 0x1F00000)
        self.assertFalse(result["kernelPhysicalHandoffVerified"])
        self.assertFalse(result["selectedRuntimeDeviceTreeVerified"])
        self.assertFalse(result["phoneModified"])

    def test_wrong_embedded_dtb_pin_fails_closed(self):
        fdt = fake_fdt()
        boot = fake_boot(fdt)
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                "dtb.img": "0" * 64}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            with (mock.patch.object(audit, "PINS", pins),
                  mock.patch.object(audit, "EXPECTED_BOOT_FILE_SIZE", len(boot))):
                with self.assertRaisesRegex(audit.AuditError, "embedded DTB"):
                    audit.analyze(root)

    def test_no_phone_ops_or_root_offsets(self):
        source = Path(audit.__file__).read_text()
        for token in ("fastboot flash", "adb shell", "setresuid(0)",
                      "FUTEX_CMP_REQUEUE_PI", "KernelSU", "sudo dd"):
            self.assertNotIn(token, source)
        self.assertIn('"kernelPhysicalHandoffVerified": False', source)


if __name__ == "__main__":
    unittest.main()
