"""Check guarded stock defconfig command; no kernel compilation or flashing."""
import argparse
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOL = Path(__file__).with_name("configure_samsung_stock_kernel.py")
# exec_module does not add sibling tools to sys.path, unlike CLI execution.
sys.path.insert(0, str(TOOL.parent))
spec = importlib.util.spec_from_file_location("config_samsung_stock", TOOL)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def mark_executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)


def good_preflight():
    return {
        "makefileVersion": {"matchesExpected": True},
        "overlayVerification": {"verified": 40},
        "deviceConfigs": {
            "single": {"matchesOfficialAudit": True},
            "openw": {"matchesOfficialAudit": True},
        },
    }


class ConfigureStockTests(unittest.TestCase):
    def make_fixture(self, tmp):
        root = Path(tmp)
        source = root / "samsung-kernel"
        source.mkdir()
        (source / "Makefile").write_text("VERSION = 4\n")
        for path in (source / "tools/dtc", root / "clang",
                     root / "aarch64-linux-gnu-gcc", root / "aarch64-linux-gnu-ld"):
            mark_executable(path)
        args = argparse.Namespace(
            source_dir=source, output_dir=root / "kconfig-output",
            audit_json=root / "audit.json", clang=root / "clang",
            gcc_prefix=str(root / "aarch64-linux-gnu-"),
            execute=False, json=None,
        )
        return args

    def test_dry_run_command_is_source_separated_and_config_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.make_fixture(tmp)
            with patch.object(config, "preflight_run", return_value=good_preflight()):
                argv, source, output = config.command_for(args)
            self.assertEqual(argv[0:3], ["make", "-C", str(source)])
            self.assertIn("REAL_CC=" + str(args.clang), argv)
            self.assertIn("CROSS_COMPILE=" + args.gcc_prefix, argv)
            self.assertIn("ARCH=arm64", argv)
            self.assertEqual(argv[-1], "vendor/y2q_usa_singlew_defconfig")
            self.assertNotIn("Image", argv)
            self.assertFalse(output.exists())

    def test_refuse_existing_output_and_source_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.make_fixture(tmp)
            args.output_dir.mkdir()
            with self.assertRaisesRegex(ValueError, "existing output"):
                config.command_for(args)
            args.output_dir = args.source_dir / "out"
            with self.assertRaisesRegex(ValueError, "separate"):
                config.command_for(args)

    def test_refuse_invalid_overlay_source_without_making_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.make_fixture(tmp)
            bad = good_preflight()
            bad["overlayVerification"]["verified"] = 39
            with patch.object(config, "preflight_run", return_value=bad):
                with self.assertRaisesRegex(ValueError, "overlay"):
                    config.command_for(args)
            self.assertFalse(args.output_dir.exists())


if __name__ == "__main__":
    unittest.main()
