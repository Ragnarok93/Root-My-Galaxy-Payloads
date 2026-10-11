#!/usr/bin/env python3
"""Synthetic-only checks of exact HXL1 AVB callback slots and caller inspection."""
from __future__ import annotations

import unittest

from tools import y2q_hxl1_avb_callback_fields as audit
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


def chain(site: str, displacement: int):
    return [
        {"kind": "operation", "opcode": "CALLIND", "distance": 0,
         "address": site, "inputs": [
             {"kind": "register", "location": "register:0x4040"}]},
        {"kind": "operation", "opcode": "LOAD", "distance": 1,
         "address": hex(int(site, 16)-16), "inputs": []},
        {"kind": "operation", "opcode": "CAST", "distance": 2,
         "address": hex(int(site, 16)-16), "inputs": []},
        {"kind": "operation", "opcode": "INT_ADD", "distance": 3,
         "address": hex(int(site, 16)-16), "inputs": [
             {"kind": "register", "location": "register:0x4000"},
             {"kind": "constant", "constantHex": format(displacement, "x")},
         ]},
        {"kind": "parameter", "distance": 4,
         "parameter": {"ordinal": 0, "name": "param_1", "data_type": "/longlong"}},
    ]


def snapshot():
    return {
        "callSlices": [
            {"module": "LinuxLoader", "callsite": site,
             "GhidraResolution": "unresolved",
             "chain": chain(site, offset)}
            for site, offset, _ in audit.EXPECTED
        ],
        "originalDossiers": {},
    }


def caller():
    return [{"line": i+1, "code": value}
            for i, value in enumerate((
                "void f() {", "  byte *pbVar20;",
                "  pbVar20 = FUN_00003000();", "  if (pbVar20 != NULL) {",
                "    *(longlong *)(pbVar20 + 0x40) = FUN_00009988;",
                "    uVar9 = FUN_00005950(pbVar20,pcVar29,pcVar34);",
                "  }", "}",
            ))]


class Hxl1AvbCallbackTests(unittest.TestCase):
    def test_three_exact_original_fields(self):
        result = audit.inspect(snapshot(), caller())
        self.assertEqual(
            [(x["callsite"], x["pcode"]["hexOffset"]) for x in result["callSites"]],
            [("0x5dc4","0x40"), ("0x5ea4","0x48"), ("0x6020","0x48")])
        self.assertEqual(result["strongerCallbackCandidate"], "0x5dc4")
        self.assertFalse(result["avbOpsLikeObjectInitializer"]["initializerVerified"])
        self.assertFalse(result["secureStateOriginProven"])
        self.assertFalse(result["unlockMethodProven"])
        self.assertEqual(
            [x["line"] for x in result["avbOpsLikeObjectInitializer"]["assignmentStatements"]],
            [3])
        self.assertEqual(
            result["aospVersionComparisons"]["legacy_no_extra_fields"]["readIsUnlockedOffset"],
            "0x38")
        self.assertEqual(
            result["aospVersionComparisons"]["newer_cert_and_preloaded_fields"]["readIsUnlockedOffset"],
            "0x48")
        self.assertIn("NOT HXL1 proof", audit.markdown(dict(
            result, originalArchiveSha256="f"*64)))

    def test_no_guess_from_anomalous_field_offset(self):
        record = snapshot()
        record["callSlices"][1]["chain"][3]["inputs"][1]["constantHex"] = "40"
        with self.assertRaisesRegex(TriageError, "callback slot differs"):
            audit.inspect(record, caller())

    def test_reject_missing_parameter_load_or_ambiguous_definitions(self):
        item = chain("0x5dc4", 0x40)
        with self.assertRaisesRegex(TriageError, "too short"):
            audit.parsed_pointer_field(item[:1] + item[2:])
        item = chain("0x5dc4", 0x40)
        item[-1]["parameter"]["ordinal"] = 1
        with self.assertRaisesRegex(TriageError, "first AVB ops parameter"):
            audit.parsed_pointer_field(item)
        item = chain("0x5dc4", 0x40)
        item[3]["inputs"][1]["constantHex"] = "41"
        with self.assertRaisesRegex(TriageError, "unaligned"):
            audit.parsed_pointer_field(item)

    def test_distinct_source_and_semantic_identity_are_not_inferred(self):
        report = snapshot()
        report["callSlices"][0]["GhidraResolution"] = "resolved-indirect"
        with self.assertRaisesRegex(TriageError, "provider-resolved"):
            audit.inspect(report, caller())
        report = snapshot()
        report["callSlices"].append(report["callSlices"][0])
        with self.assertRaisesRegex(TriageError, "Duplicate"):
            audit.inspect(report, caller())

    def test_full_caller_context_does_not_claim_initializer_from_variable(self):
        lines = caller()
        lines[2]["code"] = "  x = FUN_00003000();"
        result = audit.inspect(snapshot(), lines)
        self.assertEqual(result["avbOpsLikeObjectInitializer"]["assignmentStatements"], [])
        self.assertFalse(result["avbOpsLikeObjectInitializer"]["initializerVerified"])
        self.assertEqual(len(result["avbOpsLikeObjectInitializer"]["callToAvbConsumer"]), 1)
        lines[5]["code"] = "    other_call();"
        with self.assertRaisesRegex(TriageError, "lacks proven callback-user"):
            audit.inspect(snapshot(), lines)

    def test_line_context_and_no_new_execution(self):
        full = [{"line": i+1, "code": "x"} for i in range(500)]
        full[260]["code"] = "pbVar20 = original;"
        context = audit.related_code(full, r"\bpbVar20\b", radius=2)
        self.assertEqual(context["matchingLineNumbers"], [261])
        self.assertEqual(len(context["selectedLines"]), 5)
        from pathlib import Path
        source = Path(audit.__file__).read_text()
        for forbidden in ("subprocess", "os.system(", "fastboot flash",
                          "heimdall flash", "adb shell"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
