"""Synthetic regression tests for Samsung layered source audit (no device required)."""
import gzip
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("audit_samsung_kernel_layers.py")
BASE = "SM-G986U_NA_13_Opensource.zip"
U1 = "SM-G986U1_NA_13_Opensource_dts.zip"
HWI = "SM-G986U_13_Opensource_G986U1UES7HWI1.zip"
HXL = "SM-G986U_13_Opensource_G986USQSCHXL1_G986U1UESCHXL1_G986WVLSCHXL1.zip"
HYC = "SM-G986U_13_Opensource_G986U1UESCHYC1.zip"


def tar_gz(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


def package(name, files, tar_name):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(tar_name, tar_gz(files))
        z.writestr("README.txt", name)
    return output.getvalue()


class KernelLayerAuditTests(unittest.TestCase):
    def test_base_u1_and_update_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = root / "SM-G986U.zip"
            running = root / "config.gz"
            running.write_bytes(gzip.compress(
                b"CONFIG_FOO=y\n# CONFIG_BAR is not set\nCONFIG_BAZ=m\n"
            ))
            makefile = b"VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 113\n"
            makefile += b"# PADDED TO MATCH SAMSUNG'S >64-KiB MAKEFILE\n"
            makefile += b"#" * (65984 - len(makefile))
            with zipfile.ZipFile(wrapper, "w") as z:
                z.writestr(BASE, package(BASE, {
                    "./Makefile": makefile,
                    "./arch/arm64/configs/vendor/y2q_usa_singlew_defconfig":
                        b"CONFIG_FOO=y\n# CONFIG_BAR is not set\n",
                }, "Kernel.tar.gz"))
                z.writestr(U1, package(U1, {
                    "Kernel/arch/arm64/configs/vendor/y2q_usa_openw_defconfig":
                        b"CONFIG_FOO=y\nCONFIG_BAR=m\n",
                }, "G986U1UES8HXA1_kernel.tar.gz"))
                z.writestr(HWI, package(HWI, {
                    "Kernel/drivers/foo.c": b"old version\n",
                    "Kernel/drivers/persist.c": b"earlier unique file\n",
                }, "G986U1UES7HWI1_kernel.tar.gz"))
                z.writestr(HXL, package(HXL, {
                    "Kernel/drivers/foo.c": b"new version\n",
                    "Kernel/drivers/gpu/msm/kgsl.c": b"gpu update\n",
                }, "G986USQSCHXL1_kernel.tar.gz"))
                z.writestr(HYC, package(HYC, {
                    "Kernel/drivers/foo.c": b"do not apply HYC\n",
                }, "G986USQSCHYC1_kernel.tar.gz"))
            report = root / "report.json"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), str(wrapper),
                 "--device-config-gz", str(running), "--json", str(report)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(report.read_text())
            self.assertEqual(data["targetFirmware"], "G986U1UESCHXL1")
            self.assertEqual(data["selectedTargetArchive"], HXL)
            self.assertEqual(len(data["sourcePackages"]), 4)
            self.assertEqual(len(data["overlayStages"]), 2)
            self.assertEqual(data["earlierSourcePathsNotInHXL1Update"], 1)
            self.assertEqual(data["earlierOnlyExamples"], ["drivers/persist.c"])
            self.assertEqual(data["overlayStages"][1]["pathsOverridingPreviousLayer"], 1)
            self.assertEqual(data["overlayStages"][1]["contentDifferentWhenOverridden"], 1)
            self.assertEqual(data["sourcePackages"][0]["selectedSourceText"]["Makefile"]["kernelVersion"]["SUBLEVEL"], "113")
            self.assertEqual(data["configComparisons"]["arch/arm64/configs/vendor/y2q_usa_singlew_defconfig"]["differentExplicitSymbols"], 0)
            self.assertEqual(data["configComparisons"]["arch/arm64/configs/vendor/y2q_usa_openw_defconfig"]["differentExplicitSymbols"], 1)
            self.assertNotIn(HYC, [x["name"] for x in data["sourcePackages"]])

    def test_invalid_wrapper_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fake.zip"
            path.write_bytes(b"not zip")
            proc = subprocess.run([sys.executable, str(SCRIPT), str(path)],
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("not a ZIP", proc.stderr)


if __name__ == "__main__":
    unittest.main()
