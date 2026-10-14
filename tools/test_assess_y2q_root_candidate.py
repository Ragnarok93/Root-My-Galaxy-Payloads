"""Read-only identity and release-safety checks for the y2q assessment output."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "y2q_assess", HERE / "assess_y2q_root_candidate.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OfflineAssessmentTests(unittest.TestCase):
    def evidence(self):
        return {
            "status": "research-only",
            "identity": {
                "model": module.MODEL,
                "device": module.DEVICE,
                "firmware": module.FIRMWARE,
                "kernelRelease": module.RELEASE,
                "fingerprint": module.BUILD,
            },
            "kernelConfig": {
                "CONFIG_FUTEX_PI": "y", "CONFIG_RANDOMIZE_BASE": "y",
                "CONFIG_UH_RKP": "y", "CONFIG_SECURITY_DEFEX": "y",
            },
            "artifacts": {"boot.img": {"sha256": "aa" * 32}},
            "shizuku": {
                "uid": 2000, "flashLocked": "1",
                "selinux": "Enforcing", "procKallsymsAccessible": False,
            },
        }

    def test_candidate_remains_non_executable(self):
        report = module.make_report(self.evidence(), {"classification": "UNKNOWN"}, {})
        payload = report["candidatePayload"]
        self.assertEqual(payload["kind"], "metadata-only-non-executable")
        self.assertFalse(payload["executable"])
        self.assertFalse(payload["readyToInstall"])
        self.assertFalse(payload["rootGranted"])
        self.assertFalse(payload["allowRegistrationInSupportFeed"])
        self.assertTrue(payload["deploymentBlocked"])
        self.assertGreater(len(report["unmetGates"]), 3)

    def test_samsung_lkm_gate_is_separate_from_signature_and_hook(self):
        options = {
            "CONFIG_MODULES": "y",
            "CONFIG_MODULE_SIG_FORCE": "y",
            "CONFIG_MODULE_SIG": "y",
            "CONFIG_UH_LKM_BLOCK": "y",
            "CONFIG_UH_RKP": "y",
            "CONFIG_KPROBES": "n",
            "CONFIG_FTRACE": "y",
            "CONFIG_FUNCTION_TRACER": "n",
        }
        result = module.assess_kernel_su_stock_loading(options)
        self.assertEqual(result["moduleInfrastructure"], "CONFIGURED")
        self.assertEqual(result["mandatoryModuleSignature"], "CONFIGURED")
        self.assertEqual(result["samsungLkmBlockingConfig"], "CONFIGURED")
        self.assertEqual(result["kprobeFeature"], "NOT_CONFIGURED")
        self.assertEqual(result["functionTracerFeature"], "NOT_CONFIGURED")
        self.assertFalse(result["moduleAuthorizedToLoadProven"])
        self.assertFalse(result["kernelSu419HookBackendDemonstrated"])

    def test_unreported_vendor_options_are_not_imputed(self):
        output = module.assess_kernel_su_stock_loading(
            {"CONFIG_MODULE_SIG_FORCE": "y"})
        self.assertEqual(output["samsungLkmBlockingConfig"], "UNKNOWN_CONFIG_EVIDENCE")
        self.assertEqual(output["moduleInfrastructure"], "UNKNOWN_CONFIG_EVIDENCE")
        self.assertEqual(output["kprobeFeature"], "UNKNOWN_CONFIG_EVIDENCE")
        self.assertFalse(output["factoryKernelSuLoaded"])

    def test_candidate_includes_failsafe_stock_ksu_classification(self):
        report = module.make_report(self.evidence(), {"classification": "UNKNOWN"}, {})
        result = report["kernelSu419Integration"]
        self.assertEqual(result["classification"], "STAGE7_BLOCKED_NO_LOAD_OR_HOOK_PROOF")
        self.assertEqual(result["samsungLkmBlockingConfig"], "UNKNOWN_CONFIG_EVIDENCE")
        self.assertFalse(report["candidatePayload"]["readyToInstall"])

    def test_rejects_incorrect_firmware(self):
        wrong = self.evidence()
        wrong["identity"]["firmware"] = "unrelated"
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            module.inspect_configuration(wrong)

    def test_rejects_incorrect_kernel_prerequisites(self):
        wrong = self.evidence()
        wrong["kernelConfig"]["CONFIG_FUTEX_PI"] = "n"
        with self.assertRaisesRegex(ValueError, "CONFIG_FUTEX_PI"):
            module.inspect_configuration(wrong)

    def test_rejects_unlocked_or_rooted_runtime_in_research_manifest(self):
        wrong = self.evidence()
        wrong["shizuku"]["flashLocked"] = "0"
        with self.assertRaisesRegex(ValueError, "shell or flash lock mismatch"):
            module.make_report(wrong, {}, {})

    def test_image_sha_is_checked_before_profile_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / "boot.img"
            file.write_bytes(b"irrelevant-test-bytes")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                module.inspect_boot_file(file, "00" * 32, "boot.img")
            result = module.inspect_boot_file(file, module.sha256(file), "boot.img")
            self.assertTrue(result["verified"])


if __name__ == "__main__":
    unittest.main()
