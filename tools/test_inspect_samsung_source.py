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
                "--tar-path-regex", "^(Makefile|arch/arm64/configs/vendor/.*defconfig)$",
                "--json", str(report_path),
            ], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["entries"], 2)
            self.assertEqual(len(report["sha256"]), 64)
            self.assertEqual(report["nestedArchives"][0]["membersExamined"], 2)
            self.assertEqual(report["nestedArchives"][0]["matchedPathCount"], 2)
            self.assertEqual(len(report["nestedArchives"][0]["matchedPaths"]), 2)
            self.assertFalse(report["nestedArchives"][0]["matchedPathsTruncated"])
            self.assertEqual(report["nestedArchives"][0]["versionFromMakefile"]["VERSION"], "4")
            self.assertEqual(report["nestedArchives"][0]["versionFromMakefile"]["PATCHLEVEL"], "19")
            self.assertEqual(report["nestedArchives"][0]["versionFromMakefile"]["SUBLEVEL"], "113")
            self.assertTrue(any("defconfig" in p["path"]
                                for p in report["nestedArchives"][0]["importantPaths"]))


    def test_samsung_wrapper_with_zip_in_zip_and_nested_tar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outer = root / "SM-G986U.zip"

            tar_io = io.BytesIO()
            with tarfile.open(fileobj=tar_io, mode="w:gz") as tar:
                makefile = b"VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 113\n"
                member = tarfile.TarInfo("Makefile")
                member.size = len(makefile)
                tar.addfile(member, io.BytesIO(makefile))

            base_io = io.BytesIO()
            with zipfile.ZipFile(base_io, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("Kernel.tar.gz", tar_io.getvalue())
                archive.writestr("README.txt", "Base source fixture")

            patch_io = io.BytesIO()
            with zipfile.ZipFile(patch_io, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "HXL1 patch fixture")
                archive.writestr("kernel/drivers/test-source.c", "/* fixture */")

            patch_name = (
                "SM-G986U_13_Opensource_G986USQSCHXL1_"
                "G986U1UESCHXL1_G986WVLSCHXL1.zip"
            )
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("SM-G986U_NA_13_Opensource.zip", base_io.getvalue())
                archive.writestr(patch_name, patch_io.getvalue())

            report_path = root / "deep.json"
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(outer),
                 "--scan-nested", "--json", str(report_path)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["entries"], 2)
            self.assertEqual(len(report["nestedArchives"]), 2)
            base, patch = report["nestedArchives"]
            self.assertEqual(base["type"], "zip")
            self.assertEqual(base["entries"], 2)
            self.assertEqual(len(base["sha256"]), 64)
            self.assertEqual(base["nestedArchives"][0]["type"], "tar")
            self.assertEqual(base["nestedArchives"][0]["versionFromMakefile"]["SUBLEVEL"], "113")
            self.assertEqual(patch["type"], "zip")
            self.assertEqual(patch["name"], patch_name)
            self.assertTrue(any(p["path"] == "README.txt"
                                for p in patch["importantPaths"]))

            selected = root / "selected.json"
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(outer), "--scan-nested",
                 "--select-zip-regex", "HXL1", "--json", str(selected)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            only_hxl1 = json.loads(selected.read_text())["nestedArchives"]
            self.assertEqual(len(only_hxl1), 1)
            self.assertEqual(only_hxl1[0]["name"], patch_name)

    def test_nested_zip_size_cap_skips_without_extracting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = io.BytesIO()
            with zipfile.ZipFile(child, "w") as archive:
                archive.writestr("dummy", b"X" * (1024 * 1024 + 20))
            outer = root / "wrapper.zip"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("source.zip", child.getvalue())
            report_path = root / "cap.json"
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(outer), "--scan-nested",
                 "--max-nested-zip-mib", "1", "--json", str(report_path)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            detail = json.loads(report_path.read_text())["nestedArchives"][0]
            self.assertEqual(detail["type"], "zip")
            self.assertIn("size limit", detail["scanSkipped"])

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
