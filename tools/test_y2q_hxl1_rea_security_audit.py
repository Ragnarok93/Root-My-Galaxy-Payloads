#!/usr/bin/env python3
"""Synthetic-only contracts for HXL1 REA/Ghidra security-path workflow."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_security_audit as rea
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def evidence_obj(sha: str, operation: str, parameter: str, value: str, result: object,
                 *, arch="arm64") -> dict:
    return {
        "operation": operation, "provider": {"id": "ghidra"},
        "subject": {"digest": {"sha256": sha}, "architecture": arch},
        "parameters": {parameter: value}, "normalized_result": result,
        "evidence_id": "ev_synthetic_" + operation,
    }


def seeded_tree(root: Path) -> dict[str, str]:
    data = {"Odin": b"synthetic Odin mock", "LinuxLoader": b"synthetic loader mock"}
    hashes = {name: hashlib.sha256(blob).hexdigest() for name, blob in data.items()}
    records = []
    for index, (name, blob) in enumerate(data.items()):
        file_name = f"{index:03d}-12345678-1234-4321-8888-123456789abc-{hashes[name][:16]}.efi"
        export_dir = root / "comparison-inputs" / "HXL1" / "uefi-modules" / "abl.elf"
        export_dir.mkdir(parents=True, exist_ok=True)
        (export_dir / file_name).write_bytes(blob)
        records.append({
            "ui": name, "source": "abl.elf", "kind": "nested-uefi-pe",
            "fileName": file_name, "sha256": hashes[name],
        })
    report = {
        "schemaVersion": 1, "target": "SM-G986U1 G986U1UESCHXL1",
        "archiveSha256FromPinnedOriginalScan": rea.HXL1_BL_SHA256,
        "sourceVerified": True, "modules": records,
    }
    (root / "hxl1-bootloader-hotspots.json").write_text(json.dumps(report))
    return hashes


class Hxl1ReaTests(unittest.TestCase):
    def test_selections_require_original_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            hashes = seeded_tree(folder)
            with mock.patch.dict(rea.EXPECTED, hashes):
                selected = rea.choose_targets(folder)
                self.assertEqual([x.name for x in selected], ["Odin", "LinuxLoader"])
                self.assertTrue(all(x.path.is_file() for x in selected))
                with mock.patch.dict(rea.EXPECTED, {"Odin": "0" * 64}):
                    with self.assertRaisesRegex(TriageError, "Expected one pinned"):
                        rea.choose_targets(folder)

    def test_tampered_copy_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            hashes = seeded_tree(folder)
            file = next((folder / "comparison-inputs" / "HXL1" /
                         "uefi-modules" / "abl.elf").glob("000-*.efi"))
            file.write_bytes(b"malicious replacement")
            with mock.patch.dict(rea.EXPECTED, hashes):
                with self.assertRaisesRegex(TriageError, "SHA256 mismatch"):
                    rea.choose_targets(folder)

    def test_verified_ghidra_search_xrefs_function(self):
        sha = "d" * 64
        string = evidence_obj(sha, "search_strings", "pattern", "OEMLOCK", [
            {"address": "0x827aa", "value": "OEMLOCK"},
            {"address": "0x827bb", "value": "not important"},
        ])
        sources = evidence_obj(sha, "xrefs", "address", "0x827aa", [
            "0x4320", "0x4324", "0x4320"])
        fn_result = {
            "procedure": {
                "address": "0x4300", "name": "FUN_00004300",
                "body": {"available": True,
                         "ranges": [{"start": "0x4300", "end": "0x43ff"}]},
            },
            "pseudocode": "if (flash_unlock) { memcpy(rx_buffer,cmd,length); }",
            "native_value_flow": {"available": True},
        }
        fn = evidence_obj(sha, "analyze_function", "procedure", "0x4320", fn_result)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "evidence.json"
            for blob, op, param, value in (
                (string, "search_strings", "pattern", "OEMLOCK"),
                (sources, "xrefs", "address", "0x827aa"),
                (fn, "analyze_function", "procedure", "0x4320"),
            ):
                path.write_text(json.dumps(blob))
                verified = rea.evidence(path, sha=sha, operation=op,
                                        parameter=param, value=value)
                self.assertTrue(verified["evidence_id"])
            self.assertEqual(rea.search_hits(string, "OEMLOCK"), [
                {"address": "0x827aa", "text": "OEMLOCK"}])
            self.assertEqual(rea.reference_sources(sources), ["0x4320", "0x4324"])
            record = rea.function_record(fn, "0x4320")
            self.assertTrue(record["reviewRequired"])
            self.assertTrue(record["reviewMarkers"]["unsafe-copy-api"])
            self.assertFalse(record["vulnerabilityConfirmed"])
            self.assertFalse(record["unlockAuthorizationVerified"])
            self.assertEqual(record["entry"], "0x4300")

    def test_invalid_origin_or_query_never_becomes_verified(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.json"
            ev = evidence_obj("a" * 64, "search_strings", "pattern", "oem", [])
            path.write_text(json.dumps(ev))
            with self.assertRaisesRegex(TriageError, "provenance mismatch"):
                rea.evidence(path, sha="b" * 64, operation="search_strings",
                             parameter="pattern", value="oem")
            with self.assertRaisesRegex(TriageError, "provenance mismatch"):
                rea.evidence(path, sha="a" * 64, operation="search_strings",
                             parameter="pattern", value="unlock")
            ev["provider"]["id"] = "unknown"
            path.write_text(json.dumps(ev))
            with self.assertRaisesRegex(TriageError, "provenance mismatch"):
                rea.evidence(path, sha="a" * 64, operation="search_strings",
                             parameter="pattern", value="oem")

    def test_data_xrefs_are_not_fabricated_functions(self):
        ev = evidence_obj("f" * 64, "analyze_function", "procedure", "0x4320", {
            "procedure": {"address": "0x4300", "body":
                          {"available": True, "ranges":
                           [{"start": "0x4300", "end": "0x431f"}]}},
            "pseudocode": "return 0;",
        })
        with self.assertRaisesRegex(TriageError, "does not own xref"):
            rea.function_record(ev, "0x4320")
        self.assertEqual(rea.search_hits(
            evidence_obj("f" * 64, "search_strings", "pattern", "X", []), "X"), [])
        with self.assertRaisesRegex(TriageError, "Invalid Ghidra"):
            rea.reference_sources(
                evidence_obj("f" * 64, "xrefs", "address", "0x0", ["xyz"]))

    def test_plan_only_does_not_spawn_ghidra(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            hashes = seeded_tree(root)
            opts = argparse.Namespace(
                input_dir=root, out=root / "reports", rea=root / "absent-rea.mjs",
                node="node", execute=False, include_secure=False,
                timeout=120, max_functions=3, max_xrefs_per_seed=1,
                max_traces=0,
            )
            with mock.patch.dict(rea.EXPECTED, hashes):
                with mock.patch.object(rea.subprocess, "Popen", side_effect=AssertionError):
                    report = rea.run(opts)
            self.assertEqual(report["mode"], "PLAN_ONLY")
            self.assertTrue(report["sourceAttested"])
            self.assertEqual(len(report["targets"]), 2)
            self.assertFalse(report["bootloaderUnlockDemonstrated"])
            self.assertEqual(report["commandCount"], 12)
            self.assertTrue((root / "reports" / "security-paths.md").is_file())

    def test_valid_cached_results_are_reused_but_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "res.json"
            target = rea.Target(
                name="Odin", path=Path(td) / "image.efi",
                sha256="1" * 64, module={})
            original = evidence_obj("1" * 64, "search_strings", "pattern", "oem", [])
            path.write_text(json.dumps(original))
            runner = rea.Runner(Path(td), Path(td) / "rea.mjs")
            verified = runner.obtain(target, ["search", "image.efi", "oem"], path,
                                     operation="search_strings", parameter="pattern",
                                     value="oem")
            self.assertEqual(verified["evidence_id"], original["evidence_id"])
            self.assertEqual(runner.planned, [])
            self.assertEqual(json.loads(path.read_text()), original)

    def test_no_bootloader_flash_fuzz_or_device_actions(self):
        source = Path(rea.__file__).read_text()
        for forbidden in ("adb shell", "fastboot flash", "heimdall flash",
                          "firehose --", "os.system("):
            self.assertNotIn(forbidden, source)
        self.assertIn('"phoneModified": False', source)
        self.assertIn('"vulnerabilityDemonstrated": False', source)


if __name__ == "__main__":
    unittest.main()
