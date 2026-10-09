"""Synthetic tests for off-device Samsung stock-source assembly and traversal safety."""
import argparse
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("assemble_samsung_stock_kernel.py")
spec = importlib.util.spec_from_file_location("s20_assembly", SCRIPT)
assembly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembly)


def tar_contents(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            member.mode = 0o644
            tar.addfile(member, io.BytesIO(value))
    return out.getvalue()


def inner_zip(tar_name, files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        z.writestr(tar_name, tar_contents(files))
    return out.getvalue()


class SamsungAssemblyTests(unittest.TestCase):
    def test_path_safety(self):
        self.assertEqual(str(assembly.normalized_source_path(
            "./arch/arm64/configs/vendor/y2q_usa_singlew_defconfig")),
            "arch/arm64/configs/vendor/y2q_usa_singlew_defconfig")
        self.assertEqual(str(assembly.normalized_source_path(
            "Kernel/drivers/gpu/msm/kgsl.c")), "drivers/gpu/msm/kgsl.c")
        self.assertIsNone(assembly.normalized_source_path("Kernel"))
        for malicious in ("/tmp/evil", "../../evil", "Kernel/../evil",
                          r"Kernel\..\outside", "//etc/passwd"):
            with self.subTest(malicious=malicious):
                with self.assertRaises(ValueError):
                    assembly.normalized_source_path(malicious)

    def test_reject_absolute_symlink_and_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "source"
            target.mkdir()
            with self.assertRaises(ValueError):
                assembly.valid_symlink_target(target, target / "file", "/etc/passwd")
            assembly.valid_symlink_target(target, target / "sub/file", "../safe-link")
            (target / "bad").symlink_to("/tmp")
            with self.assertRaises(ValueError):
                assembly.check_parent_tree(target, target / "bad" / "bad-file")

    def test_end_to_end_experimental_assembly_and_reproducible_overlay_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = root / "SM-G986U.zip"
            output = root / "stock-hxl1"
            audit_file = root / "audit.json"
            final_sources = {
                "drivers/example/file_%02d.c" % i: ("HXL1-%02d\n" % i).encode()
                for i in range(40)
            }
            packages = []
            blobs = []
            base_files = {
                "./Makefile": b"VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 113\n",
                "./arch/arm64/configs/vendor/y2q_usa_singlew_defconfig":
                    b"CONFIG_ARCH_QCOM=y\n",
            }
            names = [assembly.BASE_ZIP, assembly.MODEL_ZIP] + [
                "SM-G986U_13_Opensource_REVISION%02d.zip" % i
                for i in range(8)
            ] + [
                "SM-G986U_13_Opensource_G986USQSCHXL1_"
                "G986U1UESCHXL1_G986WVLSCHXL1.zip"
            ]
            for i, name in enumerate(names):
                if i == 0:
                    data = inner_zip("Kernel.tar.gz", base_files)
                elif i == 1:
                    data = inner_zip("G986U1UES8HXA1_kernel.tar.gz", {
                        "Kernel/arch/arm64/configs/vendor/y2q_usa_openw_defconfig":
                            b"CONFIG_ARCH_QCOM=y\n",
                    })
                elif i < 10:
                    data = inner_zip("G986REV_kernel.tar.gz", {
                        "Kernel/drivers/example/file_00.c":
                            ("old-%d\n" % i).encode(),
                    })
                else:
                    data = inner_zip("G986USQSCHXL1_kernel.tar.gz", {
                        "Kernel/" + p: value for p, value in final_sources.items()
                    })
                blobs.append((name, data))
                packages.append({
                    "name": name,
                    "zipSha256": hashlib.sha256(data).hexdigest(),
                })
            with zipfile.ZipFile(wrapper, "w", zipfile.ZIP_STORED) as z:
                for name, data in blobs:
                    z.writestr(name, data)
            audit_file.write_text(json.dumps({
                "targetFirmware": assembly.PROFILE_FIRMWARE,
                "sourcePackages": packages,
                "finalSourceProvenance": {
                    path: {"source": names[-1],
                           "sizeBytes": len(value),
                           "sha256": hashlib.sha256(value).hexdigest()}
                    for path, value in final_sources.items()
                },
            }))
            args = argparse.Namespace(
                source_zip=wrapper, audit_json=audit_file, output=output,
                assemble_experimental=False
            )
            with patch.object(assembly, "PROFILE_WRAPPER_SHA256",
                              assembly.sha256_path(wrapper)):
                plan = assembly.run(args)
                self.assertFalse(plan["assembleRequested"])
                self.assertFalse(output.exists())
                args.assemble_experimental = True
                result = assembly.run(args)
            self.assertTrue(output.is_dir())
            self.assertEqual(result["finalFileVerification"]["verifiedFinalOverlayFiles"], 40)
            self.assertEqual((output / "drivers/example/file_00.c").read_bytes(),
                             b"HXL1-00\n")
            self.assertTrue((output / "Makefile").exists())
            self.assertTrue((output / "arch/arm64/configs/vendor/y2q_usa_openw_defconfig").exists())
            manifest = output.with_name(output.name + ".source-manifest.json")
            self.assertTrue(manifest.is_file())
            self.assertEqual(len(json.loads(manifest.read_text())["layerStats"]), 11)
            with patch.object(assembly, "PROFILE_WRAPPER_SHA256",
                              assembly.sha256_path(wrapper)):
                with self.assertRaisesRegex(ValueError, "output already exists"):
                    assembly.run(args)

    def test_malicious_tar_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                info = tarfile.TarInfo("../outside")
                data = b"never written"
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            buffer.seek(0)
            with self.assertRaises(ValueError):
                assembly.restore_one_tar(root, buffer, "invalid", {"totalBytes": 0})
            self.assertFalse((root.parent / "outside").exists())


if __name__ == "__main__":
    unittest.main()
