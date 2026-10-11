#!/usr/bin/env python3
"""Synthetic-only HXL1 source attestation and callback implementation tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_callback_implementations as cb
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def constructor(sha="a"*64, pseudo=None):
    if pseudo is None:
        pseudo = "\n".join((
            "undefined8 *FUN_0000b7a4(undefined8 param_1) {",
            "  undefined8 *puVar2;",
            "  puVar2 = (undefined8 *)FUN_00008cd4(0x60);",
            "  if (puVar2 != 0) {",
            "    *puVar2 = param_1;",
            "    puVar2[3] = FUN_0000a598;",
            "    puVar2[8] = FUN_0000b2bc;",
            "    puVar2[9] = &LAB_0000b30c;",
            "  }",
            "  return puVar2;",
            "}",
        ))
    return evidence_obj(sha, "analyze_function", "procedure", "0xb7a4", {
        "procedure": {"address": "0xb7a4", "name": "FUN_0000b7a4",
                      "body": {"available": True, "ranges": [
                          {"start": "0xb7a4", "end": "0xb858"}]}},
        "pseudocode": pseudo, "native_value_flow": {"available": True},
    })


def callback(sha="a"*64):
    return evidence_obj(sha, "analyze_function", "procedure", "0xb2bc", {
        "procedure": {"address": "0xb2bc", "name": "FUN_0000b2bc",
                      "body": {"available": True, "ranges": [
                          {"start": "0xb2bc", "end": "0xb30b"}]}},
        "pseudocode": "int FUN_0000b2bc(...) {\n  return secure_state();\n}",
        "native_value_flow": {"available": True},
    })


def fields():
    return {
        "allOriginalHxl1SourcesVerified": True,
        "callSites": [
            {"callsite": "0x5dc4", "pcode": {"hexOffset": "0x40"}},
            {"callsite": "0x5ea4", "pcode": {"hexOffset": "0x48"}},
            {"callsite": "0x6020", "pcode": {"hexOffset": "0x48"}},
        ],
    }


class CallbackImplementationsTests(unittest.TestCase):
    def test_exact_indexed_constructor_field_mapping(self):
        got = cb.verified_constructor_slots(constructor())
        self.assertEqual(got["allocationBytes"], 96)
        self.assertEqual([(x["slotIndex"], x["byteOffset"], x["symbol"])
                          for x in got["slots"]],
                         [(8, "+0x40", "FUN_0000b2bc"),
                          (9, "+0x48", "&LAB_0000b30c")])
        self.assertFalse(got["nativeStoreValidated"])
        self.assertFalse(got["callbackTrustSourceVerified"])

    def test_rejects_swapped_callback_slots_and_altered_constructor(self):
        ev = constructor()
        p = ev["normalized_result"]["pseudocode"]
        ev["normalized_result"]["pseudocode"] = p.replace(
            "puVar2[8] = FUN_0000b2bc", "puVar2[8] = FUN_0000b30c")
        with self.assertRaisesRegex(TriageError, "missing/conflicting"):
            cb.verified_constructor_slots(ev)
        ev = constructor(pseudo=p.replace("0x60", "0x80"))
        with self.assertRaisesRegex(TriageError, "allocation"):
            cb.verified_constructor_slots(ev)

    def test_duplicate_assigned_index_fails_closed(self):
        ev = constructor()
        ev["normalized_result"]["pseudocode"] += "\npuVar2[8] = FUN_0000b2bc;"
        with self.assertRaisesRegex(TriageError, "missing/conflicting"):
            cb.verified_constructor_slots(ev)

    def test_verified_function_analysis_keeps_security_unproved(self):
        result = cb.callback_dossier(callback())
        self.assertEqual(result["function"], "0xb2bc")
        self.assertTrue(result["pcodeAvailable"])
        self.assertFalse(result["secureStateSourceVerified"])
        self.assertFalse(result["signatureAcceptanceControlledByThisCallback"])

    def test_label_is_not_promoted_to_function_entry(self):
        ev = evidence_obj("a"*64, "inspect_native_instruction",
                          "address", "0xb30c", {
                              "address": "0xb30c", "procedure": "0xb30c",
                              "status": "decoded", "mnemonic": "stp",
                              "raw_disassembly": "stp x29, x30, [sp, #-0x10]!",
                          })
        result = cb.label_dossier(ev)
        self.assertEqual(result["nativeStatus"], "decoded")
        self.assertFalse(result["functionEntryProven"])
        ev["normalized_result"]["address"] = "0xb2bc"
        with self.assertRaisesRegex(TriageError, "Incorrect target"):
            cb.label_dossier(ev)

    def test_plan_exactly_two_read_only_original_ghidra_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            folder = root / "rea-security-audit" / "LinuxLoader"
            folder.mkdir(parents=True)
            (folder / "function-0xb7a4.json").write_text(json.dumps(constructor()))
            t = base.Target("LinuxLoader", root / "LinuxLoader-HXL1.efi",
                            "a"*64, {})
            with mock.patch.object(cb, "verify_constructor", return_value={
                "sourceAttested": True, "constructorEvidence": {"entry": "0xb7a4"},
            }), mock.patch.object(cb, "verify_field_sources",
                                 return_value=fields()), mock.patch.object(
                                     cb, "choose_targets", return_value=[t]):
                with mock.patch.object(base.subprocess, "Popen",
                                       side_effect=AssertionError("NO GHIDRA EXECUTION")):
                    got = cb.audit(root)
        self.assertEqual(got["newQueries"], 2)
        self.assertIsNone(got["lockStateCallback"])
        self.assertIsNone(got["otherCallbackLabel"])
        self.assertFalse(got["unlockDemonstrated"])

    def test_invalid_original_slot_offsets_reject_queries(self):
        bad = fields()
        bad["callSites"][2]["pcode"]["hexOffset"] = "0x40"
        with mock.patch.object(cb, "verify_constructor", return_value={
            "sourceAttested": True, "constructorEvidence": {"entry": "0xb7a4"},
        }), mock.patch.object(cb, "verify_field_sources", return_value=bad):
            with self.assertRaisesRegex(TriageError, "offsets inconsistent"):
                cb.audit(Path("/tmp/no-HXL1-source"))

    def test_tool_contains_no_device_or_flash_operations(self):
        text = Path(cb.__file__).read_text()
        for forbidden in ("fastboot flash", "heimdall flash",
                          "adb shell", "os.system(", "subprocess.Popen"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
