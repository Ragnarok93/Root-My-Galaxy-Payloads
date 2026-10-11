#!/usr/bin/env python3
"""Synthetic contract tests for original HXL1 Ghidra indirect-call attribution."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_callsite_attribution as attribution
from tools import y2q_hxl1_rea_security_audit as base
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj


def results(sha="a"*64, parent="0x5950", address="0x5dc4",
            status="unresolved", candidates=None):
    insn = evidence_obj(sha, "inspect_native_instruction", "address", address, {
        "address": address, "procedure": parent, "status": "decoded",
        "mnemonic": "blr", "raw_disassembly": "blr x8",
        "flow": {"kind": "call", "computed": True},
    })
    resolver = evidence_obj(sha, "resolve_native_call_targets", "address", address, {
        "call_site": address, "procedure": parent, "status": status,
        "mechanism": "computed", "targets": candidates or [],
        "limitations": ["No provider-supported indirect target inference"],
    })
    return insn, resolver


class CallsiteAttributionTests(unittest.TestCase):
    def test_unresolved_indirect_call_stays_unknown(self):
        insn, resolver = results()
        obs = attribution.callsite_observation(insn, resolver,
                                               parent="0x5950", address="0x5dc4")
        self.assertFalse(obs["resolvedByProvider"])
        self.assertFalse(obs["callbackSemanticIdentityEstablished"])
        self.assertEqual(obs["providerResolutionStatus"], "unresolved")
        self.assertEqual(obs["targets"], [])

    def test_provider_resolved_target_does_not_claim_security_authority(self):
        candidates = [{
            "address": "0x3000", "procedure": "0x3000",
            "status": "resolved-indirect", "basis": "provider-reference",
            "references": [],
        }]
        a, b = results(status="resolved-indirect", candidates=candidates)
        r = attribution.callsite_observation(a, b, parent="0x5950", address="0x5dc4")
        self.assertTrue(r["resolvedByProvider"])
        self.assertEqual(r["targets"][0]["address"], "0x3000")
        self.assertFalse(r["callbackSemanticIdentityEstablished"])
        self.assertFalse(r["runtimeReachabilityEstablished"])

    def test_noncall_or_wrong_owner_must_not_be_promoted(self):
        a, b = results()
        a["normalized_result"]["flow"]["kind"] = "jump"
        with self.assertRaisesRegex(TriageError, "non-indirect-call"):
            attribution.callsite_observation(a,b,parent="0x5950",address="0x5dc4")
        a, b = results()
        b["normalized_result"]["procedure"] = "0x1234"
        with self.assertRaisesRegex(TriageError, "ownership mismatch"):
            attribution.callsite_observation(a,b,parent="0x5950",address="0x5dc4")
        a, b = results()
        b["normalized_result"]["targets"] = [{"status": "candidate",
                                                "basis": "guess", "address": "0x5000"}]
        with self.assertRaisesRegex(TriageError, "Invalid original Ghidra native target"):
            attribution.callsite_observation(a,b,parent="0x5950",address="0x5dc4")

    def test_provider_dossier_requires_pinned_exact_entry_and_body(self):
        fn = evidence_obj("a"*64, "analyze_function", "procedure", "0x10e58", {
            "procedure": {
                "address": "0x10e58", "name": "FUN_00010e58",
                "body": {"available": True,
                         "ranges": [{"start": "0x10e58", "end": "0x10f80"}]},
            },
            "pseudocode": 'status = Lookup("persistent");\nreturn status;',
            "native_value_flow": {"available": True},
        })
        result = attribution.provider_dossier(fn, entry="0x10e58")
        self.assertTrue(result["pcodeAvailable"])
        self.assertEqual(result["selected"][0]["line"], 1)
        self.assertFalse(result["OEMPolicyDecisionConfirmed"])
        fn["normalized_result"]["procedure"]["address"] = "0x10e50"
        with self.assertRaisesRegex(TriageError, "provider function entry"):
            attribution.provider_dossier(fn, entry="0x10e58")

    def test_gate_rejects_changed_original_indirect_call_inventory(self):
        roots = [
            {"module": "Odin", "entry": "0x1ec00", "coveredNodes": 947,
             "totalNodes": 947, "nextOffset": None,
             "rootIndirectCallsObserved": [{"address": "0x1234"}]},
            {"module": "LinuxLoader", "entry": "0x5950", "coveredNodes": 1630,
             "totalNodes": 1630, "nextOffset": None,
             "rootIndirectCallsObserved": [{"address": x} for x in
                                            ("0x5dc4","0x5ea4","0x6020")]},
        ]
        with mock.patch.object(attribution, "verify_graph_pages",
                               return_value={"roots": roots}):
            with mock.patch.object(attribution, "choose_targets",
                                   return_value=[]):
                with self.assertRaisesRegex(TriageError, "CALLIND evidence differs"):
                    attribution.audit(Path("/tmp/fixture-origin"),
                                      execute=False)

    def test_plan_queries_exact_verified_sites_without_execution(self):
        roots = [
            {"module": "Odin", "entry": "0x1ec00", "coveredNodes": 947,
             "totalNodes": 947, "nextOffset": None,
             "rootIndirectCallsObserved": [{"address": "0x1ec84"}]},
            {"module": "LinuxLoader", "entry": "0x5950", "coveredNodes": 1630,
             "totalNodes": 1630, "nextOffset": None,
             "rootIndirectCallsObserved": [{"address": x} for x in
                                            ("0x5dc4","0x5ea4","0x6020")]},
        ]
        targets = [
            base.Target(name, Path("/tmp/original-"+name), "a"*64, {})
            for name in ("Odin", "LinuxLoader")
        ]
        with mock.patch.object(attribution, "verify_graph_pages",
                               return_value={"roots": roots}):
            with mock.patch.object(attribution, "choose_targets",
                                   return_value=targets):
                with mock.patch.object(base.subprocess, "Popen",
                                       side_effect=AssertionError("No subprocess allowed")):
                    result = attribution.audit(Path("/tmp/fixture-origin"))
        self.assertEqual(result["mode"], "PLAN_ONLY")
        self.assertEqual(result["newCommands"], 9)
        self.assertFalse(result["callbackImplementationProven"])
        self.assertFalse(result["OEMUnlockAuthorizationProven"])
        self.assertFalse(result["vulnerabilityConfirmed"])
        self.assertEqual(len(result["selectedCalls"]), 4)

    def test_no_device_command_or_patch_code(self):
        source = Path(attribution.__file__).read_text()
        for forbidden in ("fastboot flash", "heimdall flash", "adb shell",
                          "os.system(", "edl "):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
