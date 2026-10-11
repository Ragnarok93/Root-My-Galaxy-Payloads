#!/usr/bin/env python3
"""Synthetic source-integrity checks for saved HXL1 bootloader hotspot triage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import y2q_hxl1_bootloader_unlock_audit as audit
from tools import y2q_hxl1_bootloader_hotspots as hot
from tools.test_y2q_abl_linuxloader_extract import fake_abl, pe


class Hxl1HotspotsTests(unittest.TestCase):
    def make_saved(self, root: Path) -> tuple[dict, dict[str, bytes]]:
        images = {
            "abl.elf": fake_abl(),
            "tz.mbn": b"AVB verify failed\x00 Download Mode interface\x00 VaultKeeper entry",
            "vaultkeeper.mbn": b"OEM unlocking denied\x00",
        }
        originals = audit.describe(images)
        meta = {
            "schemaVersion": 1,
            "target": "SM-G986U1 G986U1UESCHXL1",
            "hxl1": {"archiveSha256": audit.HXL1_BL_SHA256},
            "hxl1Images": originals,
        }
        (root / "bootloader-unlock-candidates.json").write_text(
            json.dumps(meta, indent=2) + "\n")
        audit.export_binaries(root / "comparison-inputs", "HXL1", images)
        return meta, images

    def test_empty_and_decoded_strings(self):
        zero = hot.scan_terms(b"\x00\x01")
        self.assertEqual(zero["score"], 0)
        data = b"OEM unlocking denied\x00" + "VaultKeeper available".encode("utf-16-le")
        found = hot.scan_terms(data)
        self.assertGreater(found["counts"]["broad_unlock_mentions"], 0)
        self.assertGreater(found["counts"]["security_services"], 0)
        self.assertIn("utf16le",
                      {hit["encoding"] for hit in found["samples"]["security_services"]})

    def test_previously_saved_exports_verify_and_rank(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.make_saved(root)
            report = hot.analyze_saved(root)
            self.assertTrue(report["sourceVerified"])
            self.assertEqual(report["moduleCount"], 4)
            self.assertFalse(report["unlockMethodEstablished"])
            self.assertFalse(report["phoneModified"])
            nested = [i for i in report["modules"] if i["kind"] == "nested-uefi-pe"]
            self.assertEqual(len(nested), 1)
            self.assertEqual(nested[0]["ui"], "LinuxLoader")
            self.assertEqual(nested[0]["sha256"], hashlib.sha256(pe()).hexdigest())
            top = report["modules"][0]
            self.assertGreater(top["hints"]["score"], 0)
            md = hot.markdown(report)
            self.assertIn("file offsets; NOT runtime addresses", md)
            self.assertIn("No unlock state change", md)

    def test_tampered_outer_copy_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.make_saved(root)
            (root / "comparison-inputs" / "HXL1" / "vaultkeeper.mbn").write_bytes(
                b"spoofed")
            with self.assertRaisesRegex(audit.TriageError, "SHA256"):
                hot.analyze_saved(root)

    def test_tampered_nested_copy_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.make_saved(root)
            efi = next((root / "comparison-inputs" / "HXL1" /
                        "uefi-modules" / "abl.elf").glob("*.efi"))
            efi.write_bytes(b"spoofed")
            with self.assertRaisesRegex(audit.TriageError, "SHA256"):
                hot.analyze_saved(root)

    def test_forged_hxl1_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta, _ = self.make_saved(root)
            meta["hxl1"]["archiveSha256"] = "0" * 64
            (root / "bootloader-unlock-candidates.json").write_text(json.dumps(meta))
            with self.assertRaisesRegex(audit.TriageError, "identity mismatch"):
                hot.analyze_saved(root)

    def test_missing_export_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.make_saved(root)
            (root / "comparison-inputs" / "HXL1" / "tz.mbn").unlink()
            with self.assertRaisesRegex(audit.TriageError, "missing or symlinked"):
                hot.analyze_saved(root)

    def test_only_offline_reads(self):
        source = Path(hot.__file__).read_text()
        for banned in ("adb shell", "fastboot flash", "subprocess.run(",
                       "os.system(", "requests.get("):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
