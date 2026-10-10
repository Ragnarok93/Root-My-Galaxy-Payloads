"""Unit tests for safe ARM64 research-only bundle packing and identity gates."""
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "y2q_bundle", ROOT / "package_y2q_research_bundle.py"
)
import sys
sys.path.insert(0, str(ROOT))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DiagnosticBundleTests(unittest.TestCase):
    def candidate(self):
        return {
            "format": "root-my-galaxy-offline-research-candidate",
            "cve": "CVE-2026-43499",
            "device": {
                "model": module.MODEL, "codename": module.DEVICE,
                "firmware": module.FIRMWARE, "kernelRelease": module.RELEASE,
                "fingerprint": module.BUILD,
            },
            "candidatePayload": {
                "kind": "metadata-only-non-executable",
                "executable": False, "rootGranted": False,
                "readyToInstall": False, "deviceTested": False,
                "allowRegistrationInSupportFeed": False,
                "deploymentBlocked": True,
                "privilegeEscalationPayload": None,
                "kernelSuArtifact": None,
            },
            "unmetGates": ["manual-review", "hardware-validation"],
        }

    def elf(self):
        blob = bytearray(64)
        blob[:4] = b"\x7fELF"
        blob[4] = 2
        blob[5] = 1
        blob[16:18] = b"\x03\x00"
        blob[18:20] = b"\xb7\x00"
        return bytes(blob)

    def test_accepts_exact_identity_and_nonexecuting_candidate(self):
        candidate = self.candidate()
        module.check_candidate(candidate)
        self.assertEqual(module.check_arm64_executable(self.elf())["machine"], "AARCH64")
        with tempfile.TemporaryDirectory() as folder:
            probe = Path(folder) / "aarch64"
            out = Path(folder) / "bundle.zip"
            probe.write_bytes(self.elf())
            manifest = module.write_archive(out, candidate, probe)
            self.assertFalse(manifest["executableRootPayload"])
            with zipfile.ZipFile(out) as archive:
                names = set(archive.namelist())
                self.assertEqual(names, {"README.txt", "candidate.json",
                                         "y2q-identity-probe", "bundle-manifest.json"})
                self.assertIn("DIAGNOSTICS ONLY", archive.read("README.txt").decode())

    def test_refuses_wrong_firmware_or_deployable_candidate(self):
        obj = self.candidate()
        obj["device"]["kernelRelease"] = "other-build"
        with self.assertRaisesRegex(ValueError, "exact y2q firmware"):
            module.check_candidate(obj)
        obj = self.candidate()
        obj["candidatePayload"]["readyToInstall"] = True
        with self.assertRaisesRegex(ValueError, "nondeployable"):
            module.check_candidate(obj)

    def test_refuses_non_arm64_probe(self):
        blob = bytearray(self.elf())
        blob[18:20] = b"\x3e\x00"
        with self.assertRaisesRegex(ValueError, "not an AArch64"):
            module.check_arm64_executable(bytes(blob))


if __name__ == "__main__":
    unittest.main()
