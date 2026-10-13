"""Tests for read-only HXL1 runtime-vs-stock device-tree reconciliation."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_device_fdt_reconcile as m


def candidates():
    bases = [
        ("Qualcomm Technologies, Inc. kona v2.1 SoC", ["qcom,kona", "qcom,sm8250"]),
        ("Qualcomm Technologies, Inc. kona v2 SoC", ["qcom,kona"]),
        ("Qualcomm Technologies, Inc. kona v1 SoC", ["qcom,kona"]),
        (None, []),
    ]
    return {
        "allFdtStructuresPass": True,
        "contiguousCompleteRegionCoverage": True,
        "originalFirmwareBootAndDtbSha256Verified": True,
        "fdtHeaderCandidates": 4,
        "candidates": [
            {"index": i, "rootModel": [model] if model else [],
             "rootCompatible": compat,
             "fullStructureTokenValidation": "PASS",
             "sha256": f"{i:064x}"}
            for i, (model, compat) in enumerate(bases, 1)
        ],
    }


def snapshot(model="Qualcomm Technologies, Inc. kona v2.1 SoC",
             compatible=None):
    return {
        "schemaVersion": 1, "target": m.TARGET, "firmware": m.BUILD,
        "scope": "READ_ONLY_UNPRIVILEGED_DEVICE_IDENTITY",
        "stage4Complete": False, "stage5Complete": False, "rootVerified": False,
        "checks": {"identityConsistentWithTarget": True},
        "properties": {
            "ro.product.model": "SM-G986U1",
            "ro.product.device": "y2q",
            "ro.build.fingerprint": "test/firmware",
            "ro.build.display.id": "TP1A.G986U1UESCHXL1",
            "ro.bootloader": "G986U1UESCHXL1",
            "ro.boot.flash.locked": "1",
            "ro.boot.vbmeta.device_state": "locked",
            "ro.boot.verifiedbootstate": "green",
        },
        "deviceReads": {
            "kernelRelease": {"state": "READ", "value": "4.19.113-27095354"},
            "kernelArchitecture": {"state": "READ", "value": "aarch64"},
            "dtModel": {"state": "READ", "value": model},
            "dtCompatible": {"state": "READ", "value":
                             ["qcom,kona", "qcom,sm8250"] if compatible is None
                             else compatible},
        },
    }


def manifest():
    return {
        "identity": {
            "model": "SM-G986U1", "firmware": "G986U1UESCHXL1",
            "device": "y2q", "fingerprint": "test/firmware",
            "displayBuild": "TP1A.G986U1UESCHXL1",
            "kernelRelease": "4.19.113-27095354",
        },
        "artifacts": {
            "boot.img": {"sha256": m.stock.PINS["boot.img"]},
            "dtb.img": {"sha256": m.stock.PINS["dtb.img"]},
        },
    }


class Hxl1DeviceFdtReconcileTests(unittest.TestCase):
    def test_unique_runtime_root_identity_still_not_boot_proof(self):
        result = m.compare_dtb(snapshot(), candidates())
        self.assertEqual(result["classification"],
                         "ONE_MODEL_AND_COMPATIBLE_IDENTITY_MATCH")
        self.assertEqual(result["modelAndCompatibleMatches"], [1])
        self.assertFalse(result["selectedPhysicalDtbVerified"])
        self.assertFalse(result["kernelPhysicalHandoffVerified"])

    def test_compatible_only_is_ambiguous_not_physical_selection(self):
        result = m.compare_dtb(snapshot("Samsung overlay changed model"),
                               candidates())
        self.assertEqual(result["classification"], "COMPATIBLE_MATCH_ONLY")
        self.assertEqual(result["compatibleMatches"], [1, 2, 3])
        self.assertEqual(result["modelAndCompatibleMatches"], [])
        self.assertFalse(result["selectedPhysicalDtbVerified"])

    def test_missing_root_properties_remain_unavailable(self):
        data = snapshot()
        data["deviceReads"]["dtModel"] = {"state": "UNAVAILABLE", "value": None}
        data["deviceReads"]["dtCompatible"] = {"state": "UNAVAILABLE", "value": None}
        result = m.compare_dtb(data, candidates())
        self.assertEqual(result["classification"], "RUNTIME_PROPERTIES_UNAVAILABLE")
        self.assertFalse(result["kernelPhysicalHandoffVerified"])

    def test_no_fdt_root_match_is_not_invented(self):
        result = m.compare_dtb(snapshot("Different device", ["qcom,other"]),
                               candidates())
        self.assertEqual(result["classification"], "NO_ROOT_IDENTITY_MATCH")

    def test_malformed_or_unpinned_firmware_evidence_rejected(self):
        broken = candidates()
        broken["originalFirmwareBootAndDtbSha256Verified"] = False
        with self.assertRaisesRegex(m.ReconcileError, "incomplete"):
            m.compare_dtb(snapshot(), broken)
        broken = candidates()
        broken["candidates"][1]["fullStructureTokenValidation"] = "FAILED"
        with self.assertRaisesRegex(m.ReconcileError, "invalid original"):
            m.compare_dtb(snapshot(), broken)

    def test_device_state_distinguishes_locked_unlocked_unknown(self):
        props = snapshot()["properties"]
        self.assertEqual(m.classify_boot_state(props)["classification"],
                         "REPORTED_LOCKED")
        unlocked = {**props, "ro.boot.flash.locked": "0",
                    "ro.boot.vbmeta.device_state": "unlocked"}
        self.assertEqual(m.classify_boot_state(unlocked)["classification"],
                         "REPORTED_UNLOCKED")
        contradictory = {**props, "ro.boot.flash.locked": "0"}
        self.assertEqual(m.classify_boot_state(contradictory)["classification"],
                         "UNKNOWN_OR_CONTRADICTORY")

    def test_strict_identity_against_pinned_manifest(self):
        data = m.check_runtime_identity(snapshot(), manifest())
        self.assertTrue(data["strictManifestIdentityMatches"])
        self.assertFalse(data["originalRunningImageByteEquivalentToFirmware"])
        mismatched = snapshot()
        mismatched["properties"]["ro.build.fingerprint"] = "different"
        self.assertFalse(m.check_runtime_identity(mismatched, manifest())
                         ["strictManifestIdentityMatches"])

    def test_manifest_requires_original_pinned_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_text(json.dumps(manifest()))
            self.assertEqual(m.read_manifest(path)["identity"]["model"], m.TARGET)
            broken = manifest()
            broken["artifacts"]["dtb.img"]["sha256"] = "0" * 64
            path.write_text(json.dumps(broken))
            with self.assertRaisesRegex(m.ReconcileError, "hash differs"):
                m.read_manifest(path)

    def test_invalid_device_snapshot_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "identity.json"
            saved = snapshot()
            saved["checks"]["identityConsistentWithTarget"] = False
            path.write_text(json.dumps(saved))
            self.assertEqual(m.read_snapshot(path)["checks"]
                             ["identityConsistentWithTarget"], False)
            with self.assertRaisesRegex(m.ReconcileError, "did not pass"):
                m.check_runtime_identity(saved, manifest())
            saved["rootVerified"] = True
            path.write_text(json.dumps(saved))
            with self.assertRaisesRegex(m.ReconcileError, "privileges"):
                m.read_snapshot(path)

    def test_end_to_end_uses_saved_files_without_adb(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            source = home / "identity.json"
            source.write_text(json.dumps(snapshot()))
            reference = home / "manifest.json"
            reference.write_text(json.dumps(manifest()))
            with patch.object(m.stock, "audit", return_value=candidates()) as auditor:
                result = m.reconcile(source, home, reference)
            auditor.assert_called_once_with(home)
            self.assertTrue(result["deviceIdentity"]
                            ["strictManifestIdentityMatches"])
            self.assertEqual(result["deviceTree"]["modelAndCompatibleMatches"], [1])
            self.assertEqual(result["originalEmbeddedFdtCount"], 4)
            self.assertFalse(result["stage4Complete"])
            self.assertFalse(result["rootVerified"])
            self.assertFalse(result["deviceModified"])
            md = m.markdown(result)
            self.assertIn("Bootloader handoff and root remain unverified", md)
            self.assertIn("MODEL_AND_COMPATIBLE", md)


if __name__ == "__main__":
    unittest.main()
