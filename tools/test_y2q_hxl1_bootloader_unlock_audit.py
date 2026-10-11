#!/usr/bin/env python3
"""Synthetic-only tests for the offline HXL1/G9860 BL triage tool."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import lz4.frame
from tools import y2q_hxl1_bootloader_unlock_audit as audit


def fixture_archive(path: Path, images: dict[str, bytes], *,
                    duplicate: bool = False, link: bool = False) -> tuple[str, int]:
    with tarfile.open(path, "w") as output:
        for name, data in images.items():
            compressed = lz4.frame.compress(data)
            item = tarfile.TarInfo(name + ".lz4")
            item.size = len(compressed)
            output.addfile(item, io.BytesIO(compressed))
            if duplicate:
                output.addfile(item, io.BytesIO(compressed))
        if link:
            item = tarfile.TarInfo("abl.elf.lz4")
            item.type = tarfile.SYMTYPE
            item.linkname = "/tmp/foreign"
            output.addfile(item)
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size


class BootloaderUnlockAuditTests(unittest.TestCase):
    def test_strings_both_encodings_and_not_verdicts(self):
        text = (b"OemUnlockAllowed\x00" +
                "VaultKeeper State".encode("utf-16-le") + b"\x00\x00" +
                b"AVB verification failed\x00")
        result = audit.string_hints(text)
        self.assertGreaterEqual(result["categoryCounts"]["unlock_state"], 1)
        self.assertGreaterEqual(result["categoryCounts"]["security_services"], 1)
        self.assertGreaterEqual(result["categoryCounts"]["verified_boot"], 1)
        self.assertIn("utf16le",
                      {x["encoding"] for x in result["samples"]["security_services"]})

    def test_incomplete_elf_classified_without_fake_claim(self):
        self.assertEqual(audit.classify(b"\x7fELF" + b"\x00" * 80)["format"],
                         "ELF_UNPARSED")
        self.assertEqual(audit.classify(b"AVB0" + b"\x00" * 36)["format"],
                         "ANDROID_VBMETA_HEADER_UNVERIFIED")
        self.assertEqual(audit.classify(b"other binary")["format"],
                         "MBN_OR_OTHER_UNCLASSIFIED")

    def test_expected_archive_hash_and_size_gate(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "BL_G986U1_TEST.tar.md5"
            sha, size = fixture_archive(path, {"abl.elf": b"MZ OemUnlockAllowed"})
            info, images = audit.load_archive(path, expected_digest=sha,
                                                expected_bytes=size)
            self.assertEqual(info["archiveSha256"], sha)
            self.assertEqual(images["abl.elf"], b"MZ OemUnlockAllowed")
            with self.assertRaisesRegex(audit.TriageError, "SHA256 mismatch"):
                audit.load_archive(path, expected_digest="0" * 64,
                                   expected_bytes=size)
            with self.assertRaisesRegex(audit.TriageError, "size mismatch"):
                audit.load_archive(path, expected_digest=sha,
                                   expected_bytes=size + 1)

    def test_empty_and_invalid_archives_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            empty = root / "empty.tar.md5"
            fixture_archive(empty, {"unrelated.txt": b"data"})
            with self.assertRaisesRegex(audit.TriageError, "no expected BL images"):
                audit.load_archive(empty)
            duplicate = root / "duplicate.tar.md5"
            fixture_archive(duplicate, {"abl.elf": b"data"}, duplicate=True)
            with self.assertRaisesRegex(audit.TriageError, "duplicate"):
                audit.load_archive(duplicate)
            symlink = root / "symlink.tar.md5"
            fixture_archive(symlink, {}, link=True)
            with self.assertRaisesRegex(audit.TriageError, "nonregular"):
                audit.load_archive(symlink)

    def test_same_qualcomm_name_not_evidence_of_unlock(self):
        a = audit.describe({"abl.elf": b"OEM unlocking denied", "vbmeta.img": b"AVB0"})
        b = audit.describe({"abl.elf": b"OEM unlocking allowed", "vbmeta.img": b"AVB0"})
        report = audit.compare(a, b)
        self.assertEqual(report["abl.elf"]["status"], "DIFFERENT")
        self.assertEqual(report["vbmeta.img"]["status"], "IDENTICAL")
        self.assertEqual(report["vaultkeeper.mbn"]["status"], "MISSING_SIDE")

    def test_single_archive_baseline_and_comparison(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "inputs"
            source.mkdir()
            hxl1 = source / "BL_G986U1_HXL1.tar.md5"
            comp = source / "BL_G9860_HYA1.tar.md5"
            sha, size = fixture_archive(hxl1, {
                "abl.elf": b"MZ OEM unlocking refused\x00",
                "vbmeta.img": b"AVB0" + b"\x00" * 60,
            })
            fixture_archive(comp, {
                "abl.elf": b"MZ OEM unlocking eligible\x00",
                "vaultkeeper.mbn": b"VaultKeeper test string\x00",
            })
            out = root / "reports" / "triage"
            alone = audit.run(hxl1, None, out, pin_hash=sha, pin_bytes=size)
            self.assertEqual(alone["comparatorState"], "COMPARATOR_NOT_PROVIDED")
            self.assertFalse(alone["unlockMethodEstablished"])
            both = audit.run(hxl1, comp, out, pin_hash=sha, pin_bytes=size,
                             export=True)
            self.assertEqual(both["comparatorState"],
                             "UNVERIFIED_COMPARATOR_PROVENANCE")
            self.assertFalse(both["runtimeSecurityDecisionEstablished"])
            self.assertFalse(both["phoneModified"])
            self.assertEqual(both["comparisons"]["abl.elf"]["status"], "DIFFERENT")
            self.assertTrue((out / "bootloader-unlock-candidates.json").is_file())
            self.assertTrue((out / "comparison-inputs" / "HXL1" / "abl.elf").is_file())
            self.assertTrue((out / "comparison-inputs" / "G9860" / "abl.elf").is_file())

    def test_reject_cross_model_mislabel_and_same_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "BL_G986U1_HXL1.tar.md5"
            fixture_archive(path, {"abl.elf": b"data"})
            with self.assertRaisesRegex(audit.TriageError, "must begin BL_G9860"):
                audit.run(path, root / "wrong.tar.md5", root / "reports")
            with self.assertRaisesRegex(audit.TriageError, "same archive"):
                with mock.patch.object(Path, "name",
                        new_callable=mock.PropertyMock, return_value="BL_G9860_FAKE"):
                    audit.run(path, path, root / "reports")

    def test_reports_cannot_modify_input_folder(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inputs = root / "inputs"
            inputs.mkdir()
            path = inputs / "BL_G986U1_HXL1.tar.md5"
            sha, size = fixture_archive(path, {"abl.elf": b"data"})
            with self.assertRaisesRegex(audit.TriageError, "outside input"):
                audit.run(path, None, inputs / "analysis",
                          pin_hash=sha, pin_bytes=size)

    def test_no_firmware_execution_or_device_write_commands(self):
        source = Path(audit.__file__).read_text()
        for prohibited in ("adb shell", "fastboot flash", "heimdall flash",
                           "subprocess.run(", "os.system(", "requests.get("):
            self.assertNotIn(prohibited, source)
        self.assertIn('"phoneModified": False', source)


if __name__ == "__main__":
    unittest.main()
