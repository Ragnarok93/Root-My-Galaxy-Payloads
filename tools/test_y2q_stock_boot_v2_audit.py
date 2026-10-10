#!/usr/bin/env python3
"""Read-only v2 Android boot header parser regression tests."""
from __future__ import annotations
import importlib.util
import hashlib
from unittest import mock
from pathlib import Path
import struct
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("y2q_stock_boot_v2_audit.py")
spec = importlib.util.spec_from_file_location("y2q_stock_boot_v2_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(audit)


def fake_boot(page: int = 4096, kernel: int = 16, ramdisk: int = 8,
              second: int = 0, dtb: int = 12, recovery: int = 0) -> bytes:
    body = bytearray(page * 8)
    body[:8] = b"ANDROID!"
    struct.pack_into("<10I", body, 8, kernel, 0x80008000, ramdisk,
                     0x82000000, second, 0, 0x81000000, page, 2, 0)
    body[48:48+8] = b"S20+TEST"
    struct.pack_into("<I", body, 1632, recovery)
    struct.pack_into("<Q", body, 1636,
                     page*(3 + (1 if second else 0)) if recovery else 0)
    struct.pack_into("<I", body, 1644, 1660)
    struct.pack_into("<I", body, 1648, dtb)
    struct.pack_into("<Q", body, 1652, 0x83000000)
    return bytes(body)


class BootHeaderTests(unittest.TestCase):
    def test_v2_header_addresses_and_offsets(self):
        h = audit.boot_header(fake_boot())
        self.assertEqual(h["headerVersion"], 2)
        self.assertEqual(h["boardName"], "S20+TEST")
        self.assertEqual(h["declaredAddressFields"]["kernel_addr"], 0x80008000)
        self.assertEqual(h["declaredAddressFields"]["dtb_addr"], 0x83000000)
        self.assertEqual(h["regions"]["kernel"], {"offset": 4096, "size": 16})
        self.assertEqual(h["regions"]["ramdisk"], {"offset": 8192, "size": 8})
        self.assertEqual(h["regions"]["dtb"], {"offset": 12288, "size": 12})

    def test_recovery_dtbo_offset_and_second_stage_pages(self):
        h = audit.boot_header(fake_boot(second=32, recovery=24))
        self.assertEqual(h["regions"]["second"], {"offset": 12288, "size": 32})
        self.assertEqual(h["regions"]["recovery_dtbo"], {"offset": 16384, "size": 24})
        self.assertEqual(h["regions"]["dtb"], {"offset": 20480, "size": 12})

    def test_invalid_recovery_offset_rejected(self):
        raw = bytearray(fake_boot(recovery=100))
        struct.pack_into("<Q", raw, 1636, 1)
        with self.assertRaisesRegex(audit.AuditError, "offset"):
            audit.boot_header(bytes(raw))

    def test_truncated_boot_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "invalid/truncated"):
            audit.boot_header(b"ANDROID!")

    def test_unsupported_header_version_fails(self):
        raw = bytearray(fake_boot())
        struct.pack_into("<I", raw, 40, 3)
        with self.assertRaisesRegex(audit.AuditError, "expected"):
            audit.boot_header(bytes(raw))

    def test_out_of_bounds_rejected(self):
        raw = bytearray(fake_boot())
        struct.pack_into("<I", raw, 8, 99999999)
        with self.assertRaisesRegex(audit.AuditError, "bounds"):
            audit.boot_header(bytes(raw))

    def test_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "boot.img"
            file.write_bytes(b"wrong")
            with self.assertRaisesRegex(audit.AuditError, "SHA256"):
                audit.pinned(file, "0"*64)

    def test_only_boot_img_needed_for_declared_header_and_embedded_pin_checks(self):
        boot = fake_boot()
        kernel, ramdisk, dtb = boot[4096:4112], boot[8192:8200], boot[12288:12300]
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                "kernel.bin": hashlib.sha256(kernel).hexdigest(),
                "ramdisk.img": hashlib.sha256(ramdisk).hexdigest(),
                "dtb.img": hashlib.sha256(dtb).hexdigest()}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            with (mock.patch.object(audit, "PINS", pins),
                  mock.patch.object(audit, "EXPECTED_BOOT_BYTES", len(boot))):
                report = audit.analyze(root)
            self.assertTrue(report["originalBootImageHashVerified"])
            self.assertFalse(report["originalFileHashesVerified"])
            for component in ("kernel", "ramdisk", "dtb"):
                record = report["payloadComparisons"][component]
                self.assertEqual(record["referenceFileStatus"], "MISSING_OPTIONAL")
                self.assertIsNone(record["referenceEqualsImageRegion"])
                self.assertTrue(record["embeddedRegionMatchesPinnedSha256"])
            self.assertIn("MISSING_OPTIONAL", audit.markdown(report))

    def test_present_optional_file_matches_embedded_region(self):
        boot = fake_boot()
        payloads = {"kernel.bin": boot[4096:4112],
                    "ramdisk.img": boot[8192:8200],
                    "dtb.img": boot[12288:12300]}
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                **{name: hashlib.sha256(blob).hexdigest()
                   for name, blob in payloads.items()}}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            (root / "ramdisk.img").write_bytes(payloads["ramdisk.img"])
            with (mock.patch.object(audit, "PINS", pins),
                  mock.patch.object(audit, "EXPECTED_BOOT_BYTES", len(boot))):
                report = audit.analyze(root)
            self.assertEqual(report["separateArtifactAvailability"]["ramdisk.img"],
                             "PRESENT_PIN_VERIFIED")
            self.assertTrue(report["payloadComparisons"]["ramdisk"]["referenceEqualsImageRegion"])
            self.assertIsNone(report["payloadComparisons"]["dtb"]["referenceEqualsImageRegion"])

    def test_tampered_present_optional_file_fails_closed(self):
        boot = fake_boot()
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                "kernel.bin": hashlib.sha256(boot[4096:4112]).hexdigest(),
                "ramdisk.img": hashlib.sha256(boot[8192:8200]).hexdigest(),
                "dtb.img": hashlib.sha256(boot[12288:12300]).hexdigest()}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            (root / "ramdisk.img").write_bytes(b"tampered")
            with (mock.patch.object(audit, "PINS", pins),
                  mock.patch.object(audit, "EXPECTED_BOOT_BYTES", len(boot))):
                with self.assertRaisesRegex(audit.AuditError, "SHA256 mismatch"):
                    audit.analyze(root)

    def test_embedded_mismatch_is_reported_without_fabricating_agreement(self):
        boot = fake_boot()
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                "kernel.bin": "0" * 64,
                "ramdisk.img": hashlib.sha256(boot[8192:8200]).hexdigest(),
                "dtb.img": hashlib.sha256(boot[12288:12300]).hexdigest()}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            with (mock.patch.object(audit, "PINS", pins),
                  mock.patch.object(audit, "EXPECTED_BOOT_BYTES", len(boot))):
                report = audit.analyze(root)
            self.assertFalse(report["payloadComparisons"]["kernel"]
                             ["embeddedRegionMatchesPinnedSha256"])
            self.assertIsNone(report["payloadComparisons"]["kernel"]
                              ["referenceEqualsImageRegion"])

    def test_symlinked_optional_file_fails_closed(self):
        boot = fake_boot()
        pins = {"boot.img": hashlib.sha256(boot).hexdigest(),
                "kernel.bin": hashlib.sha256(boot[4096:4112]).hexdigest(),
                "ramdisk.img": hashlib.sha256(boot[8192:8200]).hexdigest(),
                "dtb.img": hashlib.sha256(boot[12288:12300]).hexdigest()}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "boot.img").write_bytes(boot)
            (root / "ramdisk.img").symlink_to(root / "does_not_exist")
            with (mock.patch.object(audit, "PINS", pins),
                  mock.patch.object(audit, "EXPECTED_BOOT_BYTES", len(boot))):
                with self.assertRaisesRegex(audit.AuditError, "symlinked"):
                    audit.analyze(root)

    def test_report_does_not_claim_runtime_handoff(self):
        source = SCRIPT.read_text()
        for token in ("adb shell", "fastboot flash", "sudo dd", "FUTEX_REQUEUE"):
            self.assertNotIn(token, source)
        self.assertIn('"runtimeKernelPhysicalAddressVerified": False', source)
        self.assertIn('"deviceModified": False', source)


if __name__ == "__main__":
    unittest.main()
