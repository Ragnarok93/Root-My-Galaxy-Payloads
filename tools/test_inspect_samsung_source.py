"""Smoke tests for read-only Samsung source ZIP provenance inventory."""
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "inspect_samsung_source.py"


class SourceInventoryTests(unittest.TestCase):
    def test_outer_zip_and_nested_kernel_version_are_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive_path = root / (
                "SM-G986U_13_Opensource_G986USQSCHXL1_"
                "G986U1UESCHXL1_G986WVLSCHXL1.zip"
            )
            tar_bytes = io.BytesIO()
            with tarfile.open(fileobj=tar_bytes, mode="w:gz") as tar:
                mk = b"VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 113\nEXTRAVERSION =\n"
                member = tarfile.TarInfo("Makefile")
                member.size = len(mk)
                tar.addfile(member, io.BytesIO(mk))
                config = b"CONFIG_ARCH_QCOM=y\nCONFIG_ARCH_KONA=y\n"
                member = tarfile.TarInfo("arch/arm64/configs/vendor/y2q_defconfig")
                member.size = len(config)
                tar.addfile(member, io.BytesIO(config))
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zip:
                zip.writestr("Kernel.tar.gz", tar_bytes.getvalue())
                zip.writestr("README.txt", "source package fixture")
            report_path = root / "report.json"
            proc = subprocess.run([
                sys.executable, str(TOOL), str(archive_path), "--scan-nested",
                "--json", str(report_path),
            ], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["entries"], 2)
            self.assertEqual(len(report["sha256"]), 64)
            self.assertEqual(report["nestedArchives"][0]["membersExamined"], 2)
            self.assertEqual(report["nestedArchives"][0]["versionFromMakefile"]["VERSION"], "4")
            self.assertEqual(report["nestedArchives"][0]["versionFromMakefile"]["PATCHLEVEL"], "19")
            self.assertEqual(report["nestedArchives"][0]["versionFromMakefile"]["SUBLEVEL"], "113")
            self.assertTrue(any("defconfig" in p["path"]
                                for p in report["nestedArchives"][0]["importantPaths"]))

    def test_invalid_zip_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "fake.zip"
            source.write_bytes(b"not a ZIP file")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(source)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("ZIP", proc.stderr)


if __name__ == "__main__":
    unittest.main()
