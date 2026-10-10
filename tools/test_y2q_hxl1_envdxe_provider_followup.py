#!/usr/bin/env python3
"""Isolated original-stock EnvDxe RAM provider callsite provenance tests."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_provider_followup as mod
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def parent_fixture():
    return {
        "originalEnvDxeSha256":mod.PE_SHA256,
        "startupFunctions":[{
            "label":"env-initializer", "requestedCallee":"0x1150",
            "containingFunctionEntry":"0x1150",
            "evidenceId":"ev_verified_initializer",
            "pseudocode":"longlong lVar2=thunk_FUN_000022b0(auVar1);\n",
        }],
        "diagnostics":[
            {"label":"ram-table-lib","sourceStringAddress":"0xa87e",
             "crossReferenceCount":2,
             "referenceInstructionAddresses":["0x554c","0x572c"],
             "evidenceId":"ev_ram_file"},
            {"label":"ram-entry-limit","sourceStringAddress":"0xa895",
             "crossReferenceCount":2,
             "referenceInstructionAddresses":["0x5554","0x5734"],
             "evidenceId":"ev_ram_limit"},
            {"label":"env-driver-source","sourceStringAddress":"0x90bf",
             "crossReferenceCount":9,
             "referenceInstructionAddresses":["0x1818"],
             "evidenceId":"ev_env"},
        ],
        "ramProtocolInstallerConfirmed":False,
        "kernelPhysicalLoadMeasured":False,
    }


def function_fixture(label, target, addresses):
    low=min(int(p,16) for p in addresses)
    high=max(int(p,16) for p in addresses)+0x70
    return {
        "operation":"analyze_function",
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":mod.PE_SHA256},"architecture":"arm64"},
        "parameters":{"procedure":target},
        "evidence_id":"ev_"+label,
        "normalized_result":{
            "procedure":{"address":hex(low-0x20),
                         "name":"FUN_"+f"{low-0x20:08x}",
                         "body":{
                            "available":True,
                            "provenance":"ghidra-function-body-address-set",
                            "ranges":[{"start":hex(low-0x20),"end":hex(high)}],
                         }},
            "pseudocode":"longlong test(void) { FUN_00003333(); return 0; }",
            "native_value_flow":{"available":True},
        },
    }


class OriginalEnvDxeFollowupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.parent=parent_fixture()
        self.saved={}
        for label,at,sites in mod.TARGETS:
            name="rea-envdxe-followup-"+label+".json"
            self.saved[name]=function_fixture(label,at,sites)
        self.write_all()

    def write_all(self):
        for filename,doc in self.saved.items():
            (self.folder/filename).write_text(json.dumps(doc))

    def perform(self):
        with patch.object(mod,"source_audit",return_value=self.parent):
            return mod.audit(self.folder)

    def test_three_target_functions_and_original_callsite_pairs(self):
        report=self.perform()
        self.assertEqual([q["label"] for q in report["functionDossiers"]],
                         ["initializer-dispatch","ram-table-region-a","ram-table-region-b"])
        self.assertEqual(report["functionDossiers"][1]["mustContainSourceInstructions"],
                         ["0x554c","0x5554"])
        self.assertEqual(report["functionDossiers"][2]["mustContainSourceInstructions"],
                         ["0x572c","0x5734"])

    def test_never_promotes_static_analysis_to_runtime_address_or_root(self):
        report=self.perform()
        for field in ("protocolRegistrationSiteConfirmed",
                      "getRamPartitionsCallbackConfirmed",
                      "runtimeRamPartitionEntriesObserved",
                      "kernelPhysicalLoadVerified","deviceModified"):
            self.assertFalse(report[field])
        self.assertIn("No live BaseMemory",mod.markdown(report))

    def test_parent_initializer_dispatch_is_authenticated(self):
        self.parent["startupFunctions"][0]["pseudocode"]="return 0;"
        with self.assertRaisesRegex(ExtractionError,"0x22b0"):
            self.perform()

    def test_wrong_parent_sha_rejected(self):
        self.parent["originalEnvDxeSha256"]="0"*64
        with self.assertRaisesRegex(ExtractionError,"digest mismatch"):
            self.perform()

    def test_paired_ghidra_ram_source_xrefs_required(self):
        self.parent["diagnostics"][1]["referenceInstructionAddresses"]=["0x5554"]
        with self.assertRaisesRegex(ExtractionError,"paired source references"):
            self.perform()

    def test_original_count_cannot_be_fabricated(self):
        self.parent["diagnostics"][0]["crossReferenceCount"]=3
        with self.assertRaisesRegex(ExtractionError,"paired source references"):
            self.perform()

    def test_existing_proof_must_not_be_unjustifiably_promoted(self):
        self.parent["ramProtocolInstallerConfirmed"]=True
        with self.assertRaisesRegex(ExtractionError,"incorrectly promoted"):
            self.perform()

    def test_wrong_query_address_refused(self):
        label="rea-envdxe-followup-ram-table-region-b.json"
        self.saved[label]["parameters"]["procedure"]="0x7000"
        self.write_all()
        with self.assertRaisesRegex(ExtractionError,"Wrong Ghidra"):
            self.perform()

    def test_wrong_sha_gated_before_function_body(self):
        label="rea-envdxe-followup-ram-table-region-a.json"
        self.saved[label]["subject"]["digest"]["sha256"]="0"*64
        self.write_all()
        with self.assertRaisesRegex(ExtractionError,"not bound to original"):
            self.perform()

    def test_untrusted_provider_rejected(self):
        label="rea-envdxe-followup-initializer-dispatch.json"
        self.saved[label]["provider"]["id"]="not-ghidra"
        self.write_all()
        with self.assertRaisesRegex(ExtractionError,"not bound to original"):
            self.perform()

    def test_split_ram_string_instruction_pair_not_promoted(self):
        label="rea-envdxe-followup-ram-table-region-a.json"
        self.saved[label]["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x5500","end":"0x5550"}
        ]
        self.write_all()
        with self.assertRaisesRegex(ExtractionError,"callsite"):
            self.perform()

    def test_empty_pseudocode_rejected(self):
        label="rea-envdxe-followup-ram-table-region-a.json"
        self.saved[label]["normalized_result"]["pseudocode"]=""
        self.write_all()
        with self.assertRaisesRegex(ExtractionError,"unavailable"):
            self.perform()

    def test_native_pcode_unavailable_reported_as_unavailable(self):
        label="rea-envdxe-followup-ram-table-region-b.json"
        self.saved[label]["normalized_result"]["native_value_flow"]["available"]=False
        self.write_all()
        self.assertFalse(self.perform()["functionDossiers"][2]["highFunctionPcodeAvailable"])

    def test_renamed_ghidra_function_allowed_with_verified_body(self):
        label="rea-envdxe-followup-ram-table-region-b.json"
        self.saved[label]["normalized_result"]["procedure"]["name"]="RAM_ValidatePartitions"
        self.write_all()
        self.assertEqual(self.perform()["functionDossiers"][2]["functionName"],
                         "RAM_ValidatePartitions")

    def test_call_symbols_preserved_without_claiming_function_semantics(self):
        a=self.perform()["functionDossiers"][0]
        self.assertEqual(a["observedCallSymbols"],["FUN_00003333"])
        self.assertFalse(a["callbackTableProven"])

    def test_symlink_evidence_refused(self):
        src=self.folder/"rea-envdxe-followup-ram-table-region-a.json"
        target=self.folder/"copy.json"
        target.write_bytes(src.read_bytes())
        src.unlink()
        src.symlink_to(target)
        with self.assertRaisesRegex(ExtractionError,"missing"):
            self.perform()


if __name__=="__main__":
    unittest.main()
