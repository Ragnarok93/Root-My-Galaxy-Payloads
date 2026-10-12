"""Regression tests for safe HXL1 diagnosis, build gating, ELF identity and bundle."""
import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("y2q_toolchain", ROOT / "y2q_research_toolchain.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def research_candidate():
    return {
        "format": "root-my-galaxy-offline-research-candidate",
        "cve": "CVE-2026-43499",
        "device": {
            "model": tool.MODEL, "codename": tool.DEVICE, "firmware": tool.FIRMWARE,
            "kernelRelease": tool.RELEASE, "fingerprint": tool.BUILD,
        },
        "candidatePayload": {
            "executable": False, "rootGranted": False, "deploymentBlocked": True,
            "allowRegistrationInSupportFeed": False,
        },
        "unmetGates": ["device_runtime_reachability_test"],
    }


def fake_elf():
    return b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8) + b"\x03\x00\xb7\x00" + bytes(80)


class ToolchainTests(unittest.TestCase):
    def test_exact_hxl1_scoping_and_no_foreign_profiles(self):
        good = research_candidate()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "candidate.json"
            path.write_text(json.dumps(good))
            self.assertEqual(tool.load_candidate(path), good)
            for name, value in [("firmware", "wrong"), ("kernelRelease", "4.19.113"),
                                ("model", "SM-S918B"), ("fingerprint", "other")]:
                different = research_candidate()
                different["device"][name] = value
                path.write_text(json.dumps(different))
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    tool.load_candidate(path)

    def test_root_or_feed_capable_candidates_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "candidate.json"
            for field, value in [
                ("executable", True), ("rootGranted", True),
                ("deploymentBlocked", False), ("allowRegistrationInSupportFeed", True),
            ]:
                bad = research_candidate()
                bad["candidatePayload"][field] = value
                path.write_text(json.dumps(bad))
                with self.assertRaisesRegex(ValueError, "unsafe or invalid"):
                    tool.load_candidate(path)

    def test_elf_checks_reject_x86_and_executables(self):
        with tempfile.TemporaryDirectory() as folder:
            lib = Path(folder) / "test.so"
            lib.write_bytes(fake_elf())
            tool.verify_elf_shared_aarch64(lib)
            bad = bytearray(fake_elf())
            bad[18:20] = b"\x3e\x00"
            lib.write_bytes(bad)
            with self.assertRaisesRegex(ValueError, "expected ARM64"):
                tool.verify_elf_shared_aarch64(lib)
            bad[18:20] = b"\xb7\x00"
            bad[16:18] = b"\x02\x00"
            lib.write_bytes(bad)
            with self.assertRaisesRegex(ValueError, "expected ARM64"):
                tool.verify_elf_shared_aarch64(lib)

    def test_build_only_inert_identity_library(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            ndk = base / "ndk"
            compiler = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
            compiler.parent.mkdir(parents=True)
            compiler.write_bytes(b"dummy")
            compiler.chmod(0o755)
            scan = base / "candidate.json"
            scan.write_text(json.dumps(research_candidate()))
            output = base / tool.SHARED_LIBRARY
            manifest = base / "binary.json"
            def pretend_compile(command, **kwargs):
                Path(command[-1]).write_bytes(fake_elf())
                self.assertIn("-shared", command)
                self.assertIn("-fvisibility=hidden", command)
                self.assertNotIn("src/root.c", " ".join(command))
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            args = SimpleNamespace(
                scan_report=scan, output=output, manifest=manifest, ndk=ndk,
            )
            with patch.object(tool.subprocess, "run", side_effect=pretend_compile):
                tool.command_build_probe(args)
            report = json.loads(manifest.read_text())
            self.assertEqual(report["payload"]["sha256"], tool.sha256(output))
            self.assertEqual(report["kind"], tool.RESEARCH_KIND)
            self.assertFalse(report["executableExploit"])
            self.assertFalse(report["rootVerified"])
            self.assertFalse(report["publishInSupportFeed"])
            self.assertTrue(report["deploymentBlocked"])
            with patch.object(tool.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                    tool.command_build_probe(args)
                run.assert_not_called()

    def test_bundle_is_deterministic_and_refuses_mutations(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            candidate = research_candidate()
            scan = base / "scan.json"
            scan.write_text(json.dumps(candidate))
            library = base / tool.SHARED_LIBRARY
            library.write_bytes(fake_elf())
            manifest_data = {
                "kind": tool.RESEARCH_KIND,
                "device": candidate["device"],
                "deploymentBlocked": True, "publishInSupportFeed": False,
                "executableExploit": False, "rootVerified": False,
                "kernelWriteCapability": False, "moduleLoadCapability": False,
                "scanReportSha256": tool.sha256(scan),
                "payload": {"sha256": tool.sha256(library),
                            "sizeBytes": library.stat().st_size,
                            "file": tool.SHARED_LIBRARY},
            }
            manifest = base / "binary.json"
            manifest.write_text(json.dumps(manifest_data))
            out1, out2 = base / "a.zip", base / "b.zip"
            for out in (out1, out2):
                tool.command_bundle(SimpleNamespace(
                    scan_report=scan, library=library, manifest=manifest, output=out))
            self.assertEqual(out1.read_bytes(), out2.read_bytes())
            with zipfile.ZipFile(out1) as pkg:
                self.assertEqual(
                    set(pkg.namelist()),
                    {"README.txt", "candidate.json", "diagnostic-manifest.json",
                     tool.SHARED_LIBRARY},
                )
                self.assertIn(b"NO", pkg.read("README.txt") + b" NO")
            library.write_bytes(fake_elf() + b"mutated")
            with self.assertRaisesRegex(ValueError, "manifest has wrong exact"):
                tool.command_bundle(SimpleNamespace(
                    scan_report=scan, library=library,
                    manifest=manifest, output=base / "c.zip"))

    def test_previous_automation_build_bundle_accepts_exact_legacy_filename(self):
        """Original owner run created this noncanonical diagnostic file name."""
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            candidate=research_candidate()
            scan=base/"05-cve-source-candidate.json"
            scan.write_text(json.dumps(candidate))
            library=base/tool.LEGACY_PIPELINE_LIBRARY
            library.write_bytes(fake_elf())
            manifest_data={
                "kind":tool.RESEARCH_KIND,
                "device":candidate["device"],
                "deploymentBlocked":True,"publishInSupportFeed":False,
                "executableExploit":False,"rootVerified":False,
                "kernelWriteCapability":False,"moduleLoadCapability":False,
                "scanReportSha256":tool.sha256(scan),
                "payload":{"sha256":tool.sha256(library),
                           "sizeBytes":library.stat().st_size,
                           "file":library.name},
            }
            manifest=base/"06-hxl1-identity-manifest.json"
            manifest.write_text(json.dumps(manifest_data))
            output=base/"recovered-bundle.zip"
            tool.command_bundle(SimpleNamespace(
                scan_report=scan,library=library,manifest=manifest,output=output))
            with zipfile.ZipFile(output) as zipread:
                self.assertIn(tool.LEGACY_PIPELINE_LIBRARY,zipread.namelist())
                self.assertEqual(zipread.read(tool.LEGACY_PIPELINE_LIBRARY),fake_elf())
            self.assertTrue(output.is_file())

    def test_legacy_library_rejects_alias_and_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            candidate=research_candidate()
            scan=base/"candidate.json"
            scan.write_text(json.dumps(candidate))
            library=base/tool.LEGACY_PIPELINE_LIBRARY
            library.write_bytes(fake_elf())
            manifest_data={
                "kind":tool.RESEARCH_KIND,"device":candidate["device"],
                "deploymentBlocked":True,"publishInSupportFeed":False,
                "executableExploit":False,"rootVerified":False,
                "kernelWriteCapability":False,"moduleLoadCapability":False,
                "scanReportSha256":tool.sha256(scan),
                "payload":{"sha256":tool.sha256(library),
                           "sizeBytes":library.stat().st_size,
                           "file":tool.SHARED_LIBRARY},
            }
            manifest=base/"manifest.json"
            manifest.write_text(json.dumps(manifest_data))
            args=SimpleNamespace(
                scan_report=scan,library=library,manifest=manifest,
                output=base/"unsafe.zip")
            with self.assertRaisesRegex(ValueError,"manifest has wrong exact"):
                tool.command_bundle(args)
            manifest_data["payload"]["file"]=library.name
            manifest_data["payload"]["sha256"]="0"*64
            manifest.write_text(json.dumps(manifest_data))
            with self.assertRaisesRegex(ValueError,"manifest has wrong exact"):
                tool.command_bundle(args)
            self.assertFalse(args.output.exists())

    def test_reference_matrix_does_not_claim_support(self):
        self.assertGreaterEqual(len(tool.REFERENCES), 4)
        self.assertTrue(all(r["targetMatch"] is False for r in tool.REFERENCES))
        self.assertTrue(all("repository" in r and "role" in r for r in tool.REFERENCES))


if __name__ == "__main__":
    unittest.main()
