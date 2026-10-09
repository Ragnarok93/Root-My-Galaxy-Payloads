"""Regression tests for guarded, stock-only Samsung HXL1 off-device Image build."""
import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("build_samsung_stock_kernel.py")
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("build_y2q_stock_kernel", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def create_exe(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)


def mocked_preflight():
    return {
        "makefileVersion": {"matchesExpected": True},
        "overlayVerification": {"verified": 40},
        "deviceConfigs": {"openw": {"matchesOfficialAudit": True},
                          "singlew": {"matchesOfficialAudit": True}},
    }


class ImageBuildPlanTests(unittest.TestCase):
    def setup_case(self, temporary):
        root = Path(temporary)
        source = root / "samsung-stock"
        output = root / "kconfig-clang18"
        source.mkdir()
        output.mkdir()
        makefile = source / "Makefile"
        makefile.write_text("VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 113\n")
        config = output / ".config"
        config.write_text("CONFIG_ARCH_QCOM=y\nCONFIG_CLANG_VERSION=180103\n")
        clang = root / "clang"
        cross_prefix = str(root / "aarch64-linux-gnu-")
        for executable in (clang, Path(cross_prefix + "gcc"), Path(cross_prefix + "ld"),
                           source / "tools/dtc"):
            create_exe(executable)
        comparison = {
            "firmware": module.FIRMWARE,
            "generatedConfig": str(config),
            "generatedSha256": module.sha256_file(config),
            "runningConfigGzSha256": module.RUNNING_CONFIG_GZ_SHA256,
            "generatedVsRunning": {
                "matchingExplicitSymbols": 5790,
                "differentExplicitSymbols": 1,
                "different": [{"symbol": "CONFIG_CLANG_VERSION",
                               "generated": "180103", "running": "100006"}],
                "leftOnly": [],
                "rightOnly": [f"CONFIG_MACH_UNUSED_{i:02d}" for i in range(18)],
            },
            "critical": {key: {"generated": "y", "running": "y", "match": True}
                         for key in module.CRITICAL},
        }
        comparison_path = root / "comparison.json"
        comparison_path.write_text(json.dumps(comparison))
        args = argparse.Namespace(
            source_dir=source,
            output_dir=output,
            audit_json=root / "audit.json",
            comparison_json=comparison_path,
            clang=clang,
            gcc_prefix=cross_prefix,
            jobs=2,
            execute=False,
            log=None,
            json=root / "dry-run.json",
        )
        return args, comparison, makefile, config

    def test_dry_run_uses_only_stock_image_target_and_does_not_modify_files(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            before = (makefile.read_bytes(), config.read_bytes())
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"):
                result, report_path = module.plan(args)
            self.assertEqual(result["command"][-1], "Image")
            self.assertIn("O=" + str(args.output_dir), result["command"])
            self.assertIn("REAL_CC=" + str(args.clang), result["command"])
            self.assertIn("-j2", result["command"])
            self.assertEqual(result["status"], "dry_run")
            self.assertEqual(report_path, args.json)
            self.assertEqual((makefile.read_bytes(), config.read_bytes()), before)
            self.assertFalse((args.output_dir / "arch/arm64/boot/Image").exists())

    def test_rejects_unexpected_security_difference(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            comparison["critical"]["CONFIG_UH_RKP"]["match"] = False
            with self.assertRaisesRegex(ValueError, "platform/security"):
                module.check_comparison(comparison, args.output_dir)

    def test_rejects_additional_config_delta(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            comparison["generatedVsRunning"]["different"].append(
                {"symbol": "CONFIG_MODULE_SIG_FORCE", "generated": "n", "running": "y"}
            )
            with self.assertRaisesRegex(ValueError, "exceed audited"):
                module.check_comparison(comparison, args.output_dir)

    def test_rejects_config_file_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            config.write_text("CONFIG_CLANG_VERSION=180103\nCONFIG_MODULES=n\n")
            with self.assertRaisesRegex(ValueError, "unexpected .config checksum"):
                module.plan(args)

    def test_build_requires_explicit_external_log_and_rejects_preexisting_image(self):
        with tempfile.TemporaryDirectory() as temp:
            args, comparison, makefile, config = self.setup_case(temp)
            args.execute = True
            with patch.object(module, "GENERATED_CONFIG_SHA256", module.sha256_file(config)), \
                 patch.object(module, "MAKEFILE_SHA256", module.sha256_file(makefile)), \
                 patch.object(module, "source_preflight_run", return_value=mocked_preflight()), \
                 patch.object(module.shutil, "which", return_value="/usr/bin/python"):
                with self.assertRaisesRegex(ValueError, "requires --log"):
                    module.plan(args)
                args.log = args.output_dir / "bad.log"
                with self.assertRaisesRegex(ValueError, "outside kernel source"):
                    module.plan(args)
                args.log = Path(temp) / "kernel-build.log"
                result, _ = module.plan(args)
                self.assertEqual(result["log"], str(args.log))
                image = args.output_dir / "arch/arm64/boot/Image"
                image.parent.mkdir(parents=True)
                image.write_bytes(b"already compiled")
                with self.assertRaisesRegex(ValueError, "Image already exists"):
                    module.plan(args)


if __name__ == "__main__":
    unittest.main()
