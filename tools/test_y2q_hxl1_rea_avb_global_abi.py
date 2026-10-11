#!/usr/bin/env python3
"""Regression tests for original HXL1 void-source vs byte-call ABI evidence."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_global_abi as abi
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_avb_state_source import callback
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def source(sha="a"*64, pseudo=None):
    if pseudo is None:
        pseudo = "\n".join((
            "void FUN_00033770(void)",
            "{",
            "  longlong lVar1;",
            "  char cVar2;",
            "  lVar1 = DAT_0032a4b8;",
            "  cVar2 = FUN_00039cdc();",
            "  if (cVar2 != 0 && (cVar2 = FUN_00039d08(0x80000000)) != 0) {",
            '    FUN_00039818(0x80000000,"%a : (%d)\\n","IsUnlocked",DAT_00351055);',
            "  }",
            "  if (DAT_0032a4b8 == lVar1) {",
            "    return;",
            "  }",
            "  FUN_0001e81c(DAT_00351055);",
            "}",
        ))
    return evidence_obj(sha, "analyze_function", "procedure", "0x33770", {
        "procedure": {
            "address": "0x33770", "name": "FUN_00033770",
            "body": {"available": True, "ranges": [
                {"start": "0x33770", "end": "0x33810"}]},
        },
        "pseudocode": pseudo, "native_value_flow": {"available": True},
    })


class Hxl1AbiTests(unittest.TestCase):
    def test_original_return_type_mismatch_is_explicit(self):
        result = abi.competing_decompilations(callback(), source())
        self.assertTrue(result["abiReturnTypeInconsistent"])
        self.assertTrue(result["sourceDecompilesVoid"])
        self.assertEqual(result["globalCandidateOtherUses"][0]["line"], 8)
        self.assertEqual(len(result["globalCandidateOtherUses"]), 2)
        self.assertFalse(result["returnRegisterDefinitionVerified"])
        self.assertFalse(result["originalGlobalIsStateProducerVerified"])

    def test_changed_global_or_return_signature_fails_closed(self):
        bad = source()
        bad["normalized_result"]["pseudocode"] = (
            bad["normalized_result"]["pseudocode"].replace(
                "DAT_00351055", "DAT_00351054"))
        with self.assertRaisesRegex(TriageError, "context differs"):
            abi.competing_decompilations(callback(), bad)
        bad = source()
        bad["normalized_result"]["pseudocode"] = (
            bad["normalized_result"]["pseudocode"].replace(
                "void FUN_00033770", "char FUN_00033770"))
        with self.assertRaisesRegex(TriageError, "void-function"):
            abi.competing_decompilations(callback(), bad)
        bad = source()
        bad["normalized_result"]["pseudocode"] = (
            bad["normalized_result"]["pseudocode"].replace(
                "return;", "return 1;"))
        with self.assertRaisesRegex(TriageError, "value-returning"):
            abi.competing_decompilations(callback(), bad)

    def test_native_instruction_presentation_preserves_unrecognized_format(self):
        ev = evidence_obj("a"*64, "read_function_instructions", "procedure",
                          "0xb2bc", {"unexpected": [1]})
        got = abi.instruction_observation(ev, entry="0xb2bc")
        self.assertFalse(got["recordsRecognized"])
        self.assertFalse(got["nativeReturnRegisterVerified"])
        ev["normalized_result"] = [
            {"address": "0xb2bc", "mnemonic": "stp", "operands": "x29,x30"},
            {"address": "0xb2c0", "mnemonic": "bl", "operands": "0x33770"},
            {"address": "0xb2c4", "mnemonic": "strb", "operands": "w0, [x1]"},
        ]
        got = abi.instruction_observation(ev, entry="0xb2bc")
        self.assertEqual(got["recordCount"], 3)
        self.assertEqual(got["records"][2]["fields"]["mnemonic"], "strb")
        self.assertFalse(got["nativeReturnRegisterVerified"])

    def test_instruction_output_is_bounded(self):
        ev = evidence_obj("a"*64, "read_function_instructions", "procedure",
                          "0x33770", [{"address": hex(x*4)} for x in range(220)])
        got = abi.instruction_observation(ev, entry="0x33770")
        self.assertEqual(len(got["records"]), 210)
        self.assertTrue(got["displayTruncated"])

    def test_plan_selects_exactly_four_static_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            folder = root / "rea-security-audit" / "LinuxLoader"
            folder.mkdir(parents=True)
            (folder / "function-0xb2bc.json").write_text(json.dumps(callback()))
            (folder / "function-0x33770.json").write_text(json.dumps(source()))
            target = base.Target("LinuxLoader", root / "LinuxLoader-HXL1.efi",
                                 "a"*64, {})
            with mock.patch.object(abi, "validate_state_source",
                                   return_value={
                                       "originalHXL1ProvenanceVerified": True,
                                       "sourceProvider": {"entry": "0x33770"},
                                   }), mock.patch.object(abi, "choose_targets",
                                                        return_value=[target]), \
                 mock.patch.object(base.subprocess, "Popen",
                                   side_effect=AssertionError("Unexpected REA")):
                report = abi.audit(root)
        self.assertEqual(report["queriesRequested"], 4)
        self.assertEqual([x["entry"] for x in report["instructions"]],
                         ["0xb2bc", "0x33770"])
        self.assertEqual([x["address"] for x in report["globalReferences"]],
                         ["0x351055", "0x32a4b8"])
        self.assertEqual(report["mode"], "PLAN_ONLY")
        self.assertFalse(report["trustAuthorityEstablished"])
        self.assertFalse(report["unlockedBootloader"])
        self.assertFalse(report["firmwareModified"])

    def test_saved_xrefs_are_not_reclassified_as_writes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            folder = root / "rea-security-audit" / "LinuxLoader"
            folder.mkdir(parents=True)
            (folder / "function-0xb2bc.json").write_text(json.dumps(callback()))
            (folder / "function-0x33770.json").write_text(json.dumps(source()))
            original = evidence_obj("a"*64, "xrefs", "address", "0x351055",
                                    ["0x3379c", "0x337dc"])
            (folder / "xrefs-global-0x351055.json").write_text(json.dumps(original))
            target = base.Target("LinuxLoader", root / "LinuxLoader-HXL1.efi",
                                 "a"*64, {})
            with mock.patch.object(abi, "validate_state_source",
                                   return_value={
                                       "originalHXL1ProvenanceVerified": True,
                                       "sourceProvider": {"entry": "0x33770"},
                                   }), mock.patch.object(abi, "choose_targets",
                                                        return_value=[target]):
                report = abi.audit(root)
        self.assertEqual(report["queriesRequested"], 3)
        self.assertEqual(report["globalReferences"][0]["sourceCount"], 2)
        self.assertEqual(report["globalReferences"][0]["readerWriterClassification"],
                         "UNKNOWN")

    def test_no_direct_firmware_or_device_tools(self):
        raw = Path(abi.__file__).read_text()
        for forbidden in ("fastboot flash", "adb shell", "heimdall flash",
                          "subprocess.Popen(", "os.system("):
            self.assertNotIn(forbidden, raw)


if __name__ == "__main__":
    unittest.main()
