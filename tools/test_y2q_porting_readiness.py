#!/usr/bin/env python3
"""Regression tests for the research-only HXL1 nine-stage porting report."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("y2q_porting_readiness.py")
spec = importlib.util.spec_from_file_location("y2q_porting_readiness", SCRIPT)
port = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(port)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PortTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[dict, Path, Path, Path]:
        artifacts = root / "s20-artifacts"
        vendor = root / "samsung"
        repo = root / "repo"
        (vendor / "kernel/locking").mkdir(parents=True)
        (repo / "support").mkdir(parents=True)
        (repo / "src/targets").mkdir(parents=True)
        artifacts.mkdir(parents=True)
        blobs = {"boot.img": b"known boot", "kernel.bin": b"known kernel",
                 "config.gz": b"known config"}
        for name, blob in blobs.items():
            (artifacts / name).write_bytes(blob)
        sources = {"kernel/locking/rtmutex.c": b"known rtmutex",
                   "kernel/futex.c": b"known futex"}
        for name, blob in sources.items():
            (vendor / name).write_bytes(blob)
        self.expected_sources = {path: sha(blob) for path, blob in sources.items()}
        (repo / "support/targets-v3.json").write_text('{"targets":[]}')
        e = {
            "profileId": port.PROFILE + "-research",
            "identity": {
                "model": port.MODEL, "firmware": port.FIRMWARE,
                "kernelRelease": port.KERNEL,
            },
            "artifacts": {
                name: {"sha256": sha(blob), "sizeBytes": len(blob)}
                for name, blob in blobs.items()
            },
            "nativeIdentityProbe": {"verifiedHardwareExecution": True},
            "hxl1LiveBootSecurityState20261010": {
                "model": port.MODEL, "kernel": port.KERNEL,
            },
            "hxl1RtmutexFixReferenceAudit": {
                "ownerAuditExecution": {"status": "PASS_SOURCE_AUDIT_ONLY"}
            },
            "originalFirmwareBinaryVerification": {
                "elfRecovery": {"instructionCorrelation": {
                    "tested": [{"equal": True}, {"equal": True}]}}
            },
        }
        return e, artifacts, vendor, repo

    def test_all_nine_stages_classified_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            data, artifacts, vendor, repo = self.fixture(Path(td))
            stock_elf = artifacts / "hxl1-research/vmlinux-stock.elf"
            stock_elf.parent.mkdir(parents=True)
            stock_elf.write_bytes(b"recovered ELF")
            (stock_elf.parent / "vmlinux-stock.nm").write_text("0000 T _text\n")
            with mock.patch.object(port, "STOCK_HASHES", self.expected_sources):
                report = port.analyze(data, artifacts, vendor, repo)
            self.assertEqual(len(report["gates"]), 9)
            self.assertEqual(report["completedStages"], [1, 2])
            self.assertEqual(report["gates"][2]["state"], "PARTIAL")
            self.assertEqual(report["gates"][3]["state"], "OPEN")
            self.assertEqual(report["gates"][6]["state"], "BLOCKED")
            self.assertFalse(report["payloadPortCompleted"])
            self.assertFalse(report["phoneChanged"])
            self.assertIn("nine-stage", port.summary(report))

    def test_wrong_firmware_or_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data, *_ = self.fixture(Path(td))
            data["identity"]["firmware"] = "OTHER"
            with self.assertRaisesRegex(port.GateError, "identity mismatch"):
                port.validate_evidence(data)
            data["identity"]["firmware"] = port.FIRMWARE
            data["profileId"] = "different-research"
            with self.assertRaisesRegex(port.GateError, "not the verified"):
                port.validate_evidence(data)

    def test_artifact_hash_mismatch_stops_before_report(self):
        with tempfile.TemporaryDirectory() as td:
            data, artifacts, *_ = self.fixture(Path(td))
            (artifacts / "kernel.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(port.GateError, "kernel.bin differs"):
                port.artifacts_check(data, artifacts)

    def test_source_mismatch_stops_before_report(self):
        with tempfile.TemporaryDirectory() as td:
            _, _, vendor, _ = self.fixture(Path(td))
            with mock.patch.object(port, "STOCK_HASHES", self.expected_sources):
                (vendor / "kernel/futex.c").write_bytes(b"tampered")
                with self.assertRaisesRegex(port.GateError, "source hash mismatch"):
                    port.source_check(vendor)

    def test_raw_btf_header_checks_full_bounds_not_four_byte_prefix(self):
        with tempfile.TemporaryDirectory() as td:
            kernel = Path(td) / "kernel.bin"
            kernel.write_bytes(b"xxxx\x9f\xeb\x01\x00short")
            result = port.btf_candidates(kernel)
            self.assertEqual(result["status"], "NO_RAW_BTF_CANDIDATE")
            data = bytearray(128)
            struct.pack_into("<HBBIIIII", data, 16, 0xEB9F, 1, 0,
                             24, 0, 4, 4, 8)
            data[16 + 24 + 4] = 0
            kernel.write_bytes(data)
            result = port.btf_candidates(kernel)
            self.assertEqual(result["status"], "ONE_RAW_BTF_CANDIDATE")
            self.assertEqual(result["candidates"][0]["fileOffset"], "0x10")

    def test_unverified_production_registration_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            data, artifacts, vendor, repo = self.fixture(Path(td))
            (repo / "support/targets-v3.json").write_text(
                '{"targets":[{"name":"SM-G986U1"}]}')
            with mock.patch.object(port, "STOCK_HASHES", self.expected_sources):
                with self.assertRaisesRegex(port.GateError, "production support feed"):
                    port.analyze(data, artifacts, vendor, repo)

    def test_stage4_manifest_verified_does_not_claim_physical_handoff(self):
        with tempfile.TemporaryDirectory() as td:
            data, artifacts, vendor, repo = self.fixture(Path(td))
            data["hxl1Stage4BootloaderDiscovery"] = {
                "archive": {
                    "sha256": "f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b",
                    "fileEntriesCount": 27,
                },
                "ownerBootloaderElfAuditVerified": {
                    "regression": {"passed": 10},
                    "artifactIntegrity": "[PASS] original ELF and hashes",
                },
                "followupBootImageV2Audit": {
                    "regression": {"passed": 13},
                    "bootImageIntegrity": "PRESENT_PIN_VERIFIED",
                    "embeddedComponents": {
                        "kernel": {"checksumPinMatch": True},
                        "ramdisk": {"checksumPinMatch": True},
                        "dtb": {"checksumPinMatch": True},
                    },
                },
                "followupFdtStructureAndRootIdentity": {
                    "regression": {"passed": 10},
                    "bootAndEmbeddedDtbSha256Verified": True,
                    "contiguousCompleteRegionCoverage": True,
                    "allFdtStructuresPass": True,
                    "candidates": [{"tokenStatus": "PASS"} for _ in range(4)],
                },
            }
            with mock.patch.object(port, "STOCK_HASHES", self.expected_sources):
                report = port.analyze(data, artifacts, vendor, repo)
            stage4 = report["gates"][3]
            self.assertEqual(stage4["state"], "OPEN")
            self.assertNotIn("Locate matching HXL1 BL archive", stage4["nextProof"])
            self.assertIn("selected DTB", stage4["nextProof"])
            self.assertIn("BL/ELF verified=True", stage4["evidence"])
            manifest = report["factoryStage4EvidenceFromManifest"]
            self.assertTrue(manifest["ownerManifestVerifiesExactHxl1BL"])
            self.assertTrue(manifest["ownerManifestVerifiesBootV2AndEmbeddedPayloads"])
            self.assertTrue(manifest["ownerManifestVerifiesFourFdtTokenStreams"])
            self.assertFalse(manifest["actualKernelPhysicalLoadVerified"])
            self.assertFalse(manifest["runtimeSelectedDtbVerified"])
            self.assertIn("Actual physical Linux kernel handoff: **NOT VERIFIED**",
                          port.summary(report))
            self.assertEqual(report["completedStages"], [1, 2])

    def test_stage4_manifest_incomplete_or_mismatched_is_not_promoted(self):
        data = {"hxl1Stage4BootloaderDiscovery": {
            "archive": {"sha256": "0" * 64, "fileEntriesCount": 27},
            "ownerBootloaderElfAuditVerified": {
                "regression": {"passed": 10},
                "artifactIntegrity": "[PASS] untrusted",
            },
            "followupBootImageV2Audit": {
                "regression": {"passed": 13},
                "bootImageIntegrity": "PRESENT_PIN_VERIFIED",
                "embeddedComponents": {
                    "kernel": {"checksumPinMatch": True},
                    "ramdisk": {"checksumPinMatch": False},
                    "dtb": {"checksumPinMatch": True},
                },
            },
            "followupFdtStructureAndRootIdentity": {
                "regression": {"passed": 10},
                "bootAndEmbeddedDtbSha256Verified": True,
                "contiguousCompleteRegionCoverage": True,
                "allFdtStructuresPass": True,
                "candidates": [{"tokenStatus": "PASS"} for _ in range(3)],
            },
        }}
        report = port.stage4_factory_evidence(data)
        self.assertFalse(report["ownerManifestVerifiesExactHxl1BL"])
        self.assertFalse(report["ownerManifestVerifiesBootV2AndEmbeddedPayloads"])
        self.assertFalse(report["ownerManifestVerifiesFourFdtTokenStreams"])
        self.assertFalse(report["actualKernelPhysicalLoadVerified"])
        self.assertFalse(report["runtimeSelectedDtbVerified"])

    def test_does_not_compile_or_touch_phone(self):
        source = SCRIPT.read_text()
        for term in (
            "adb push", "adb shell", "fastboot flash",
            "init_module(", "FUTEX_CMP_REQUEUE_PI",
            "FUTEX_WAIT_REQUEUE_PI", "TARGET_CFLAGS :=",
        ):
            self.assertNotIn(term, source)
        self.assertIn('"kernelSuLoaded": False', source)
        self.assertIn('"payloadPortCompleted": False', source)


if __name__ == "__main__":
    unittest.main()
