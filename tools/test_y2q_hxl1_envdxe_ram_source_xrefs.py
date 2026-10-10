#!/usr/bin/env python3
"""Offline negative/positive fixtures for original EnvDxe source-xrefs phase."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_ram_source_xrefs as mod
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def fixture_baseline():
    return {
        "originalEnvDxeSha256":mod.PE_SHA256,
        "guidXrefsEvidenceId":"ev_guid_xrefs_0",
        "entryFunction":{
            "evidenceId":"ev_entry",
            "pseudocode":
                "param_1=FUN_000010f4();\n"
                "FUN_00001150(param_1,param_2,param_3);\n",
        },
        "stringSearches":[
            {"label":"ram-partition", "hits":[
                {"address":"0xa87e","value":"RamPartitionTableLib.c"},
                {"address":"0xa895","value":"mRamPartitionTableEntryCount <= 4"}
            ]},
            {"label":"env-driver","hits":[
                {"address":"0x90bf","value":"EnvDxe.c"}]},
            {"label":"get-ram-partitions","hits":[]},
        ],
    }


def ev(operation,parameter,result,label):
    parameters = ({"address":parameter} if operation=="xrefs" else
                  {"procedure":parameter})
    return {
        "operation":operation,
        "parameters":parameters,
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":mod.PE_SHA256},
                   "architecture":"arm64"},
        "evidence_id":"ev_fixture_"+label,
        "normalized_result":result,
    }


def func(code,at):
    return {
        "procedure":{
            "address":at,
            "name":"FUN_"+at.removeprefix("0x").zfill(8),
            "body":{"available":True,
                    "provenance":"ghidra-function-body-address-set",
                    "ranges":[{"start":at,"end":hex(int(at,16)+0x100)}]}
        },
        "pseudocode":code,
        "native_value_flow":{"available":True},
    }


class RamSourceXrefEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.baseline=fixture_baseline()
        self.evidence={}
        for label,_,coordinate,_ in mod.TARGET_STRING_XREFS:
            self.evidence["rea-envdxe-xrefs-"+label+".json"] = ev(
                "xrefs",coordinate,["0x2218","0x2248"],label)
        for label,coordinate,_ in mod.TARGET_FUNCTIONS:
            self.evidence["rea-envdxe-function-"+label+".json"] = ev(
                "analyze_function",coordinate,
                func("void FUN(void) { return; }",coordinate),label)
        self.persist_all()

    def persist(self,key):
        (self.folder/key).write_text(json.dumps(self.evidence[key]))

    def persist_all(self):
        for key in self.evidence:
            self.persist(key)

    def analyze(self):
        with patch.object(mod,"entry_strings_audit",return_value=self.baseline):
            return mod.audit(self.folder)

    def test_source_refs_and_actual_callees_verified(self):
        report=self.analyze()
        self.assertEqual(len(report["diagnostics"]),3)
        self.assertEqual(len(report["startupFunctions"]),2)
        self.assertEqual(report["startupFunctions"][1]["requestedCallee"],"0x1150")
        self.assertEqual(report["diagnostics"][1]["sourceStringAddress"],"0xa895")
        self.assertFalse(report["ramProtocolInstallerConfirmed"])
        self.assertFalse(report["kernelPhysicalLoadMeasured"])
        self.assertFalse(report["deviceModified"])

    def test_zero_xrefs_is_valid_and_not_registration_absence(self):
        key="rea-envdxe-xrefs-ram-entry-limit.json"
        self.evidence[key]["normalized_result"]=[]
        self.persist(key)
        record=self.analyze()["diagnostics"][1]
        self.assertEqual(record["crossReferenceCount"],0)
        self.assertIn("not proof",mod.render(self.analyze()))

    def test_duplicated_refs_keep_count_and_unique_sources(self):
        key="rea-envdxe-xrefs-ram-table-lib.json"
        self.evidence[key]["normalized_result"]=["0x2220","0x2220"]
        self.persist(key)
        rec=self.analyze()["diagnostics"][0]
        self.assertEqual(rec["crossReferenceCount"],2)
        self.assertEqual(rec["referenceInstructionAddresses"],["0x2220"])

    def test_incorrect_source_address_rejected(self):
        key="rea-envdxe-xrefs-ram-entry-limit.json"
        self.evidence[key]["parameters"]["address"]="0xa894"
        self.persist(key)
        with self.assertRaisesRegex(ExtractionError,"xref target mismatch"):
            self.analyze()

    def test_foreign_original_pe_digest_refused(self):
        key="rea-envdxe-xrefs-env-driver-source.json"
        self.evidence[key]["subject"]["digest"]["sha256"]="0"*64
        self.persist(key)
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.analyze()

    def test_wrong_provider_refused(self):
        key="rea-envdxe-function-env-initializer.json"
        self.evidence[key]["provider"]["id"]="other"
        self.persist(key)
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.analyze()

    def test_malformed_reference_address_refused(self):
        key="rea-envdxe-xrefs-ram-table-lib.json"
        self.evidence[key]["normalized_result"]=["0x1234;unexpected"]
        self.persist(key)
        with self.assertRaisesRegex(ExtractionError,"Malformed"):
            self.analyze()

    def test_function_requested_callee_not_covered_by_body(self):
        key="rea-envdxe-function-env-initializer.json"
        self.evidence[key]["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x9000","end":"0x9100"}]
        self.persist(key)
        with self.assertRaisesRegex(ExtractionError,"not in Ghidra"):
            self.analyze()

    def test_function_can_be_renamed_if_body_is_proven(self):
        key="rea-envdxe-function-env-initializer.json"
        self.evidence[key]["normalized_result"]["procedure"]["name"]="EFI_InitHandler"
        self.persist(key)
        self.assertEqual(self.analyze()["startupFunctions"][1]["name"],"EFI_InitHandler")

    def test_pseudocode_required(self):
        key="rea-envdxe-function-startup-helper.json"
        self.evidence[key]["normalized_result"]["pseudocode"]=""
        self.persist(key)
        with self.assertRaisesRegex(ExtractionError,"decompilation absent"):
            self.analyze()

    def test_native_pcode_absence_is_not_fabricated(self):
        key="rea-envdxe-function-startup-helper.json"
        self.evidence[key]["normalized_result"]["native_value_flow"]["available"]=False
        self.persist(key)
        result=self.analyze()
        self.assertFalse(result["startupFunctions"][0]["highFunctionPcodeAvailable"])

    def test_original_entry_call_graph_is_precondition(self):
        self.baseline["entryFunction"]["pseudocode"]="return 0;"
        with self.assertRaisesRegex(ExtractionError,"call graph changed"):
            self.analyze()

    def test_string_mismatch_rejected(self):
        self.baseline["stringSearches"][0]["hits"][1]["value"]="Other"
        with self.assertRaisesRegex(ExtractionError,"not proven"):
            self.analyze()

    def test_report_does_not_claim_runtime_entry_count(self):
        result=self.analyze()
        rendered=mod.render(result)
        self.assertIn("compiled check, not a measured DRAM layout",rendered)
        self.assertIn("No runtime BaseMemory",rendered)


if __name__=="__main__":
    unittest.main()
