"""Synthetic read-only stock config comparison tests."""
import gzip
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("compare_samsung_kernel_configs.py")
spec = importlib.util.spec_from_file_location("compare_s20_kernel_configs", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConfigComparisonTests(unittest.TestCase):
    def test_generated_running_and_source_comparisons(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated = root / ".config"
            running = root / "config.gz"
            source = root / "y2q_usa_singlew_defconfig"
            generated.write_text(
                "CONFIG_ARCH_QCOM=y\nCONFIG_ARCH_KONA=y\n"
                "# CONFIG_MODULE_SIG_FORCE is not set\n"
                "CONFIG_ONLY_GENERATED=y\n"
            )
            running.write_bytes(gzip.compress(
                b"CONFIG_ARCH_QCOM=y\nCONFIG_ARCH_KONA=y\n"
                b"CONFIG_MODULE_SIG_FORCE=y\n"
                b"CONFIG_ONLY_RUNNING=y\n"
            ))
            source.write_text(
                "CONFIG_ARCH_QCOM=y\nCONFIG_ARCH_KONA=y\n"
                "CONFIG_MODULE_SIG_FORCE=y\n"
            )
            with patch.object(module, "EXPECTED_RUNNING_SHA256",
                              module.file_sha256(running)):
                with patch.object(module, "EXPECTED_DEFCONFIG_SHA256",
                                  module.file_sha256(source)):
                    result = module.run(generated, running, source)
            stats = result["generatedVsRunning"]
            self.assertEqual(stats["matchingExplicitSymbols"], 2)
            self.assertEqual(stats["differentExplicitSymbols"], 1)
            self.assertEqual(stats["leftOnly"], ["CONFIG_ONLY_GENERATED"])
            self.assertEqual(stats["rightOnly"], ["CONFIG_ONLY_RUNNING"])
            self.assertFalse(result["critical"]["CONFIG_MODULE_SIG_FORCE"]["match"])
            self.assertEqual(result["sourceVsGenerated"]["differentExplicitSymbols"], 1)

    def test_refuse_unknown_running_config_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated = root / ".config"
            running = root / "config.gz"
            generated.write_text("CONFIG_ARM64=y\n")
            running.write_bytes(gzip.compress(b"CONFIG_ARM64=y\n"))
            with self.assertRaisesRegex(ValueError, "captured S20"):
                module.run(generated, running)

    def test_empty_and_duplicate_conflict_behavior(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / "config"
            file.write_text("CONFIG_TEST=y\nCONFIG_TEST=n\n")
            values, duplicates = module.read_config(file)
            self.assertEqual(values["CONFIG_TEST"], "n")
            self.assertEqual(duplicates["CONFIG_TEST"]["first"], "y")
            file.write_text("not a kernel config")
            with self.assertRaisesRegex(ValueError, "no CONFIG"):
                module.read_config(file)


if __name__ == "__main__":
    unittest.main()
