"""Synthetic tests of the read-only Samsung stock-kernel build preflight."""
import argparse
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("preflight_samsung_stock_build.py")
spec = importlib.util.spec_from_file_location("s20_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class BuildPreflightTests(unittest.TestCase):
    def test_good_source_config_audit_and_manifest_without_build(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent / "stock"
            root.mkdir()
            (root / "Makefile").write_text(
                "VERSION = 4\nPATCHLEVEL = 19\nSUBLEVEL = 113\nEXTRAVERSION =\nNAME = \"People's Front\"\n")
            stock_config = b"CONFIG_ARCH_QCOM=y\nCONFIG_ARCH_KONA=y\n"
            checksum = hashlib.sha256(stock_config).hexdigest()
            for name in preflight.CONFIGS:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(stock_config)
            overlay_file = root / "drivers/test.c"
            overlay_file.parent.mkdir(parents=True, exist_ok=True)
            overlay_file.write_bytes(b"/* stock */\n")
            overlay_hash = preflight.digest(overlay_file)
            provenance = {f"drivers/file_{i:02d}.c": {"sha256": None}
                          for i in range(39)}
            for key in provenance:
                filename = root / key
                filename.write_bytes(b"/* stock */\n")
                provenance[key]["sha256"] = overlay_hash
            provenance["drivers/test.c"] = {"sha256": overlay_hash}
            audit = parent / "audit.json"
            audit.write_text(json.dumps({
                "targetFirmware": preflight.EXPECTED_FIRMWARE,
                "finalSourceProvenance": provenance,
            }))
            manifest = Path(str(root) + ".source-manifest.json")
            manifest.write_text(json.dumps({
                "targetFirmware": preflight.EXPECTED_FIRMWARE,
                "finalFileVerification": {"verifiedFinalOverlayFiles": 40},
            }))
            arguments = argparse.Namespace(
                source_dir=root, audit_json=audit, clang_path=None,
                gcc_prefix="", linker_path=None, json=None,
            )
            with patch.object(preflight, "EXPECTED_CONFIG_SHA256", checksum):
                result = preflight.run(arguments)
            self.assertTrue(result["makefileVersion"]["matchesExpected"])
            self.assertEqual(result["makefileVersion"]["extra"], "")
            self.assertEqual(result["overlayVerification"]["verified"], 40)
            self.assertTrue(all(d["matchesOfficialAudit"] for d in
                                result["deviceConfigs"].values()))
            self.assertTrue((root / "Makefile").is_file())
            self.assertFalse((root / "out").exists())
            self.assertFalse(result["kernelCompiled"])
            self.assertEqual(result["kernelBootable"], "not tested")

    def test_refuses_wrong_firmware(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit = root / "audit.json"
            audit.write_text('{"targetFirmware":"G986U1UESCHYC1"}')
            args = argparse.Namespace(source_dir=root, audit_json=audit)
            with self.assertRaisesRegex(ValueError, "firmware mismatch"):
                preflight.run(args)


if __name__ == "__main__":
    unittest.main()
