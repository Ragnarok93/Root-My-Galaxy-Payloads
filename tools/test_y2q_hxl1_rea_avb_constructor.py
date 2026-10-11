#!/usr/bin/env python3
"""Synthetic-only HXL1 original AvbOps-constructor dossier regression gates."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_constructor as constructor
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_decision_path_review import make_saved_evidence
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def original_2274(sha: str, source: str = "0x3f34"):
    return evidence_obj(sha, "analyze_function", "procedure", source, {
        "procedure": {"address": "0x2274", "name": "original",
                      "body": {"available": True, "ranges": [
                          {"start": "0x2274", "end": "0x3fff"}]}},
        "pseudocode": "\n".join((
            "void FUN_00002274(void) {",
            "  pbVar20 = (byte *)0x0;",
            "  if (pcVar19 != NULL) {",
            "    pbVar20 = (byte *)FUN_0000b7a4(pcVar19);",
            "    if (pbVar20 == (byte *)0x0) { return; }",
            "    uVar9 = FUN_00005950(pbVar20,pcVar29,pcVar34);",
            "  }",
            "  pbVar20 = param_1; // cleanup-path artifact",
            "}",
        )),
        "native_value_flow": {"available": True},
    })


def original_b7a4(sha: str, entry: str = "0xb7a4"):
    return evidence_obj(sha, "analyze_function", "procedure", "0xb7a4", {
        "procedure": {"address": entry, "name": "original",
                      "body": {"available": True, "ranges": [
                          {"start": "0xb7a4", "end": "0xb858"}]}},
        "pseudocode": "\n".join((
            "longlong FUN_0000b7a4(char *name) {",
            "  object = FUN_0000abcd(0x100);",
            "  *(code **)(object + 0x40) = FUN_00003400;",
            "  *(code **)(object + 0x48) = FUN_00005600;",
            "  if (object == NULL) return 0;",
            "  return object;",
            "}",
        )),
        "native_value_flow": {"available": True},
    })


class Hxl1ConstructorTests(unittest.TestCase):
    def test_original_caller_verifies_assignment_and_consumer(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = make_saved_evidence(root)
            file = root / "rea-security-audit/LinuxLoader/function-0x3f34.json"
            file.write_text(json.dumps(original_2274(sha["LinuxLoader"])))
            data = constructor.attest_original_caller(root, sha["LinuxLoader"])
        self.assertEqual(data["caller"], "0x2274")
        self.assertEqual(data["constructorAssignmentLine"], 4)
        self.assertEqual(data["consumerLine"], 6)
        self.assertFalse(data["dominationOrControlFlowProven"])

    def test_refuses_wrong_original_constructor_or_missing_call(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = make_saved_evidence(root)["LinuxLoader"]
            file = root / "rea-security-audit/LinuxLoader/function-0x3f34.json"
            wrong = original_2274(sha)
            wrong["normalized_result"]["pseudocode"] = (
                wrong["normalized_result"]["pseudocode"].replace(
                    "FUN_0000b7a4(pcVar19)", "FUN_0000b7b8(pcVar19)"))
            file.write_text(json.dumps(wrong))
            with self.assertRaisesRegex(TriageError, "missing or ambiguous"):
                constructor.attest_original_caller(root, sha)

    def test_constructor_dossier_collects_pseudocode_without_promoting_assignments(self):
        ev = original_b7a4("a"*64)
        result = constructor.inspect_constructor(ev)
        self.assertEqual(result["entry"], "0xb7a4")
        self.assertEqual(result["totalLines"], 7)
        self.assertIn(3, result["fieldOffsetCandidateLines"])
        self.assertIn(4, result["fieldOffsetCandidateLines"])
        self.assertFalse(result["callbacksAssignedVerified"])
        self.assertFalse(result["trustedSourceOfStateIdentified"])
        self.assertTrue(result["fullPseudocodeSha256"])
        md = constructor.markdown({
            "originalArchiveSha256": "f"*64, "mode": "MOCK",
            "queryCommands": 0, "caller": {
                "originalCallerEvidenceId": "e", "constructorAssignmentLine": 4,
                "constructorAssignment": "pbVar20 = (byte *)FUN_0000b7a4(pcVar19);",
                "consumerLine": 6,
                "consumerStatement": "uVar9 = FUN_00005950(pbVar20,pcVar29,pcVar34);",
            },
            "constructorEvidence": result,
        })
        self.assertIn("requires actual STORE/dataflow", md)

    def test_wrong_constructor_entry_rejected(self):
        ev = original_b7a4("a"*64)
        ev["normalized_result"]["procedure"]["address"] = "0xbbb0"
        with self.assertRaisesRegex(TriageError, "does not own|constructor entry"):
            constructor.inspect_constructor(ev)

    def test_plan_mode_makes_one_query_without_launching_ghidra(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sha = make_saved_evidence(root)
            targets = [base.Target(n, root / n, sha[n], {}) for n in
                       ("Odin", "LinuxLoader")]
            with mock.patch.object(constructor, "validate_saved_fields",
                                   return_value={"allOriginalHxl1SourcesVerified": True}):
                with mock.patch.object(constructor, "choose_targets",
                                       return_value=targets):
                    with mock.patch.object(constructor, "attest_original_caller",
                                           return_value={
                                               "caller": "0x2274",
                                               "originalCallerEvidenceId": "e",
                                               "constructorAssignmentLine": 343,
                                               "consumerLine": 437,
                                           }):
                        with mock.patch.object(base.subprocess, "Popen",
                                               side_effect=AssertionError("never launch REA")):
                            result = constructor.audit(root)
        self.assertEqual(result["queryCommands"], 1)
        self.assertIsNone(result["constructorEvidence"])
        self.assertFalse(result["bootloaderUnlocked"])
        self.assertFalse(result["callbackTableInitializerProven"])
        self.assertEqual(result["constructorFunction"], "0xb7a4")

    def test_no_firmware_flash_or_phone(self):
        source = Path(constructor.__file__).read_text()
        for forbidden in ("fastboot flash", "heimdall flash", "adb shell",
                          "edl firehose", "os.system("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
