#!/usr/bin/env python3
"""20 provenance and negative-evidence fixtures for RAM callback and xrefs."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_ram_registration_callback as mod
from tools.test_y2q_hxl1_envdxe_ram_registration_interface import (
    initial_prior, item_record,
)
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def refs(label,at,values=None):
    return {
        "operation":"xrefs",
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":mod.PE_SHA256},"architecture":"arm64"},
        "parameters":{"address":at},
        "evidence_id":"ev_xrefs_"+label,
        "normalized_result":values if values is not None else ["0x2060","0x2064"],
    }


def fn(at="0x3420"):
    return {
        "operation":"analyze_function",
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":mod.PE_SHA256},"architecture":"arm64"},
        "parameters":{"procedure":at},
        "evidence_id":"ev_callback",
        "normalized_result":{
            "procedure":{
                "address":"0x3400","name":"FUN_00003400",
                "body":{"available":True,
                        "provenance":"ghidra-function-body-address-set",
                        "ranges":[{"start":"0x3400","end":"0x3498"}]},
            },
            "pseudocode":"undefined8 FUN_00003400(void){ FUN_00005111(); return 0; }",
            "native_value_flow":{"available":True},
        },
    }


class OriginalProtocolXrefAndCallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.previous=initial_prior()
        self.saved={mod.READ_EVIDENCE:item_record()}
        for name,at in mod.XREF_TARGETS:
            self.saved["rea-envdxe-ram-protocol-xrefs-"+name+".json"]=refs(name,at)
        self.saved[mod.CALLBACK_EVIDENCE]=fn()
        self.persist_all()

    def persist_all(self):
        for filename,data in self.saved.items():
            (self.folder/filename).write_text(json.dumps(data))

    def write(self,name):
        (self.folder/name).write_text(json.dumps(self.saved[name]))

    def overall(self):
        with patch.object(mod,"prior_audit",return_value=self.previous):
            return mod.audit(self.folder)

    def test_four_distinct_source_xrefs(self):
        outcome=self.overall()
        self.assertEqual(len(outcome["targetedOriginalXrefs"]),4)
        self.assertEqual([x["queriedStaticAddress"]
                          for x in outcome["targetedOriginalXrefs"]],
                         ["0xd1d0","0xd1e8","0x205c","0x53b0"])

    def test_combined_register_and_callback_categories_separate(self):
        outcome=self.overall()
        self.assertTrue(outcome["staticRegistrationCallPatternVerified"])
        self.assertTrue(outcome["staticCallbackFunctionIdentified"])
        self.assertFalse(outcome["runtimeRegistrationSuccessful"])
        self.assertFalse(outcome["rootOrKernelSuAchieved"])
        self.assertFalse(outcome["kernelPhysicalLoadMeasured"])
        self.assertFalse(outcome["deviceModified"])

    def test_callback_function_inside_body_and_original_digest(self):
        result=mod.callback_function(self.folder,"0x3420")
        self.assertEqual(result["owningFunctionEntry"],"0x3400")
        self.assertEqual(result["originalEvidenceId"],"ev_callback")
        self.assertEqual(result["observedCallees"],["FUN_00003400","FUN_00005111"])
        self.assertFalse(result["actualRuntimeCallbackExecutionObserved"])

    def test_no_direct_xrefs_is_not_missing_interface(self):
        name,at=mod.XREF_TARGETS[0]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        self.saved[key]["normalized_result"]=[]
        self.write(key)
        check=mod.xref_evidence(self.folder,name,at)
        self.assertEqual(check["referenceCount"],0)
        self.assertFalse(check["actualBootExecutionObserved"])

    def test_duplicate_xrefs_keep_absolute_count_and_unique_sources(self):
        name,at=mod.XREF_TARGETS[2]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        self.saved[key]["normalized_result"]=["0x2064","0x2064"]
        self.write(key)
        result=mod.xref_evidence(self.folder,name,at)
        self.assertEqual(result["referenceCount"],2)
        self.assertEqual(result["sourceInstructionAddresses"],["0x2064"])

    def test_xref_wrong_target_refused(self):
        name,_=mod.XREF_TARGETS[1]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        self.saved[key]["parameters"]["address"]="0xd118"
        self.write(key)
        with self.assertRaisesRegex(ExtractionError,"xref target"):
            self.overall()

    def test_xref_foreign_digest_rejected(self):
        name,_=mod.XREF_TARGETS[3]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        self.saved[key]["subject"]["digest"]["sha256"]="0"*64
        self.write(key)
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.overall()

    def test_xref_wrong_provider_refused(self):
        name,_=mod.XREF_TARGETS[0]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        self.saved[key]["provider"]["id"]="unknown"
        self.write(key)
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.overall()

    def test_xref_malformed_instruction_rejected(self):
        name,_=mod.XREF_TARGETS[3]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        self.saved[key]["normalized_result"]=["0x2064;bad"]
        self.write(key)
        with self.assertRaisesRegex(ExtractionError,"Malformed"):
            self.overall()

    def test_xref_unbounded_rejected(self):
        name,_=mod.XREF_TARGETS[2]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        self.saved[key]["normalized_result"]=["0x2000"]*(mod.MAX_REFS+1)
        self.write(key)
        with self.assertRaisesRegex(ExtractionError,"unbounded"):
            self.overall()

    def test_callback_wrong_query_refused(self):
        self.saved[mod.CALLBACK_EVIDENCE]["parameters"]["procedure"]="0x0"
        self.write(mod.CALLBACK_EVIDENCE)
        with self.assertRaisesRegex(ExtractionError,"request mismatch"):
            self.overall()

    def test_callback_wrong_original_sha_refused(self):
        self.saved[mod.CALLBACK_EVIDENCE]["subject"]["digest"]["sha256"]="0"*64
        self.write(mod.CALLBACK_EVIDENCE)
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.overall()

    def test_callback_body_outside_target_refused(self):
        self.saved[mod.CALLBACK_EVIDENCE]["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x1000","end":"0x2000"}]
        self.write(mod.CALLBACK_EVIDENCE)
        with self.assertRaisesRegex(ExtractionError,"not inside authentic"):
            self.overall()

    def test_callback_without_pseudocode_rejected(self):
        self.saved[mod.CALLBACK_EVIDENCE]["normalized_result"]["pseudocode"]=""
        self.write(mod.CALLBACK_EVIDENCE)
        with self.assertRaisesRegex(ExtractionError,"absent"):
            self.overall()

    def test_callback_native_pcode_unavailable_is_not_hidden(self):
        self.saved[mod.CALLBACK_EVIDENCE]["normalized_result"]["native_value_flow"]["available"]=False
        self.write(mod.CALLBACK_EVIDENCE)
        self.assertFalse(self.overall()["staticCallbackFunction"]["highFunctionPcodeAvailable"])

    def test_callback_missing_function_body_classification_refused(self):
        self.saved[mod.CALLBACK_EVIDENCE]["normalized_result"]["procedure"]["body"]["provenance"]="other"
        self.write(mod.CALLBACK_EVIDENCE)
        with self.assertRaisesRegex(ExtractionError,"not inside authentic"):
            self.overall()

    def test_zero_unrelocated_callback_needs_no_fake_function_file(self):
        self.saved[mod.READ_EVIDENCE]=item_record((0,0,0,0,0,0))
        self.write(mod.READ_EVIDENCE)
        (self.folder/mod.CALLBACK_EVIDENCE).unlink()
        report=self.overall()
        self.assertIsNone(report["staticCallbackFunction"])
        self.assertFalse(report["staticCallbackFunctionIdentified"])
        self.assertTrue(report["protocolInterfaceStructure"]
                        ["callbackMayRequireRelocationsOrRuntimeInitialization"])
        self.assertFalse(report["runtimeRegistrationSuccessful"])

    def test_nonzero_but_unusable_pointer_is_not_decompiled(self):
        self.saved[mod.READ_EVIDENCE]=item_record((0,0,0,0xffffffffffffffff,0,0))
        self.write(mod.READ_EVIDENCE)
        report=self.overall()
        self.assertIsNone(report["staticCallbackFunction"])
        self.assertIn("relocation",mod.markdown(report).lower())

    def test_symlinked_xref_evidence_refused(self):
        name,_=mod.XREF_TARGETS[0]
        key="rea-envdxe-ram-protocol-xrefs-"+name+".json"
        file=self.folder/key
        backup=self.folder/"xref_original.json"
        backup.write_bytes(file.read_bytes())
        file.unlink()
        file.symlink_to(backup)
        with self.assertRaisesRegex(ExtractionError,"missing"):
            self.overall()

    def test_output_retains_full_pseudocode_and_static_only_limits(self):
        report=self.overall()
        doc=mod.markdown(report)
        self.assertIn("FUN_00005560",doc)
        self.assertIn("callback function static decompilation",doc.lower())
        self.assertIn("boot-time success",doc)
        self.assertIn("KernelSU",doc)


if __name__=="__main__":
    unittest.main()
