#!/usr/bin/env python3
"""Synthetic regression tests for exact HXL1 0xb2bc -> 0x33770 provenance."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_state_source as state
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def callback(sha="a"*64, pseudo=None):
    if pseudo is None:
        pseudo = "\n".join((
            "undefined8 FUN_0000b2bc(undefined8 param_1,undefined1 *param_2) {",
            "  undefined1 uVar1;",
            "  undefined8 uVar3;",
            "  if (param_2 == (undefined1 *)0x0) {",
            "    uVar3 = 2;",
            "  }",
            "  else {",
            "    uVar1 = FUN_00033770();",
            "    uVar3 = 0;",
            "    *param_2 = uVar1;",
            "  }",
            "  return uVar3;",
            "}",
        ))
    return evidence_obj(sha, "analyze_function", "procedure", "0xb2bc", {
        "procedure": {"address": "0xb2bc", "name": "FUN_0000b2bc",
                      "body": {"available": True, "ranges": [
                          {"start": "0xb2bc", "end": "0xb30b"}]}},
        "pseudocode": pseudo, "native_value_flow": {"available": True},
    })


def source(sha="a"*64, address="0x33770"):
    return evidence_obj(sha, "analyze_function", "procedure", "0x33770", {
        "procedure": {"address": address, "name": "FUN_00033770",
                      "body": {"available": True, "ranges": [
                          {"start": "0x33770", "end": "0x33850"}]}},
        "pseudocode": "\n".join((
            "undefined1 FUN_00033770(void) {",
            "  x = DAT_000a2340;",
            "  value = FUN_00036660(x);",
            "  if (value == 1) return 1;",
            "  return 0;",
            "}",
        )),
        "native_value_flow": {"available": True},
    })


class Hxl1AvbSourceTests(unittest.TestCase):
    def test_wrapper_has_verified_separate_status_and_output(self):
        facts = state.verify_wrapper(callback())
        self.assertEqual(facts["sourceFunction"], "0x33770")
        self.assertEqual(facts["nullOutputStatusInPseudocode"], 2)
        self.assertEqual(facts["nonNullOutputStatusInPseudocode"], 0)
        self.assertEqual(facts["observations"]["sourceReadCall"]["line"], 8)
        self.assertEqual(facts["observations"]["outputByteAssignment"]["line"], 10)
        self.assertFalse(facts["runtimeBehaviorOrSecurityAuthorityProven"])

    def test_modified_call_rejected_before_gathering_new_evidence(self):
        cb = callback()
        cb["normalized_result"]["pseudocode"] = (
            cb["normalized_result"]["pseudocode"].replace(
                "FUN_00033770()", "FUN_00033774()"))
        with self.assertRaisesRegex(TriageError, "sourceReadCall"):
            state.verify_wrapper(cb)
        cb = callback()
        cb["normalized_result"]["pseudocode"] = (
            cb["normalized_result"]["pseudocode"].replace(
                "uVar3 = 2;", "uVar3 = 0;"))
        with self.assertRaisesRegex(TriageError, "nullError2|success0"):
            state.verify_wrapper(cb)

    def test_null_pointer_output_and_ambiguous_pseudocode_rejected(self):
        cb = callback()
        cb["normalized_result"]["pseudocode"] = (
            cb["normalized_result"]["pseudocode"].replace(
                "*param_2 = uVar1;", "*param_2 = 1;"))
        with self.assertRaisesRegex(TriageError, "outputByteAssignment"):
            state.verify_wrapper(cb)
        cb = callback()
        cb["normalized_result"]["pseudocode"] += "\nuVar1 = FUN_00033770();"
        with self.assertRaisesRegex(TriageError, "ambiguous sourceReadCall"):
            state.verify_wrapper(cb)

    def test_provider_dossier_keeps_globals_calls_as_references(self):
        d = state.source_dossier(source())
        self.assertEqual(d["entry"], "0x33770")
        self.assertEqual(d["fullPseudocodeLineCount"], 6)
        self.assertEqual(d["globalReferences"][0]["address"], "0xa2340")
        self.assertTrue(any(x["entry"] == "0x36660" for x in d["functionReferences"]))
        self.assertFalse(d["trustAnchorIdentified"])
        self.assertFalse(d["sourceSecurityAuthorityProven"])

    def test_wrong_owner_rejected(self):
        ev = source(address="0x33774")
        with self.assertRaisesRegex(TriageError, "does not own|identity"):
            state.source_dossier(ev)

    def test_one_query_plan_is_offline_and_not_a_security_bypass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            directory = root / "rea-security-audit" / "LinuxLoader"
            directory.mkdir(parents=True)
            (directory / "function-0xb2bc.json").write_text(json.dumps(callback()))
            target = base.Target(
                "LinuxLoader", root / "LinuxLoader-HXL1.efi",
                "a"*64, {})
            with mock.patch.object(state, "verify_callback_implementations",
                                   return_value={
                                       "originalEvidencesAttested": True,
                                       "lockStateCallback": {"owningProcedure": "0xb2bc"},
                                       "otherCallbackLabel": {"address": "0xb30c"},
                                   }), mock.patch.object(
                                       state, "choose_targets",
                                       return_value=[target]), mock.patch.object(
                                           base.subprocess, "Popen",
                                           side_effect=AssertionError("NO Ghidra")):
                report = state.audit(root)
        self.assertEqual(report["queriesRequested"], 1)
        self.assertIsNone(report["sourceProvider"])
        self.assertFalse(report["actualSecurityStateOriginVerified"])
        self.assertFalse(report["signatureOrOdinPolicyBypassVerified"])
        self.assertFalse(report["deviceBootloaderUnlocked"])
        self.assertFalse(report["handsetModified"])

    def test_preserved_original_provider_is_cached_offline(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            directory = root / "rea-security-audit" / "LinuxLoader"
            directory.mkdir(parents=True)
            (directory / "function-0xb2bc.json").write_text(json.dumps(callback()))
            (directory / "function-0x33770.json").write_text(json.dumps(source()))
            target = base.Target("LinuxLoader", root / "LinuxLoader-HXL1.efi", "a"*64, {})
            with mock.patch.object(state, "verify_callback_implementations",
                                   return_value={
                                       "originalEvidencesAttested": True,
                                       "lockStateCallback": {"owningProcedure": "0xb2bc"},
                                       "otherCallbackLabel": {"address": "0xb30c"},
                                   }), mock.patch.object(
                                       state, "choose_targets",
                                       return_value=[target]), mock.patch.object(
                                           base.subprocess, "Popen",
                                           side_effect=AssertionError("NO Ghidra")):
                report = state.audit(root)
        self.assertEqual(report["queriesRequested"], 0)
        self.assertEqual(report["sourceProvider"]["entry"], "0x33770")

    def test_no_firmware_execution_device_flash_or_mutation(self):
        program = Path(state.__file__).read_text()
        for dangerous in ("fastboot flash", "heimdall flash", "adb shell",
                          "subprocess.Popen", "os.system("):
            self.assertNotIn(dangerous, program)


if __name__ == "__main__":
    unittest.main()
