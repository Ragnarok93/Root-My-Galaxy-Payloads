#!/usr/bin/env python3
"""Synthetic original-EnvDxe table input and protocol-init provenance tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_ram_table_input_trace as p
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def verified_parent():
    return {
        "originalEnvDxeSha256":p.PE_SHA256,
        "protocolRegistrationSiteConfirmed":False,
        "runtimeRamPartitionEntriesObserved":False,
        "functionDossiers":[
            {"label":"initializer-dispatch","functionEntry":"0x22b0",
             "evidenceId":"ev_init", "pseudocode":
                "FUN_000023b0(arg);\nFUN_000020ac();"},
            {"label":"ram-table-region-a","functionEntry":"0x5430",
             "evidenceId":"ev_ram_1", "pseudocode":
                'FUN_00003c3c(foo);\n'
                '"mRamPartitionTableEntryCount <= 4"'},
            {"label":"ram-table-region-b","functionEntry":"0x5560",
             "evidenceId":"ev_ram_2", "pseudocode":
                "FUN_000053b0(foo);\nFUN_00005430(bar);\n"
                "DAT_0000d700 = 0x60000000;\n"
                "DAT_0000d6f8 = 0x80000000;\n"
                '"mRamPartitionTableEntryCount <= 4"'},
        ]
    }


def function_result(at,label):
    return {
        "operation":"analyze_function","provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":p.PE_SHA256},"architecture":"arm64"},
        "parameters":{"procedure":at},
        "evidence_id":"ev_"+label,
        "normalized_result":{
            "procedure":{
                "address":at,"name":"FUN_"+at[2:].zfill(8),
                "body":{"available":True,
                        "provenance":"ghidra-function-body-address-set",
                        "ranges":[{"start":at,"end":hex(int(at,16)+128)}]},
            },
            "pseudocode":"undefined8 process(void) { FUN_00004444(); return 0; }",
            "native_value_flow":{"available":True},
        },
    }


class OriginalRamTableInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.parent=verified_parent()
        self.saved={}
        for label,at,_ in p.FUNCTION_TARGETS:
            self.saved["rea-envdxe-input-trace-"+label+".json"]=function_result(at,label)
        self.saved["rea-envdxe-input-trace-"+p.XREF_LABEL+".json"]={
            "operation":"xrefs","provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":p.PE_SHA256},"architecture":"arm64"},
            "parameters":{"address":p.XREF_TARGET},
            "evidence_id":"ev_table_references",
            "normalized_result":["0x2340","0x234c"],
        }
        self.write()

    def write(self):
        for name,value in self.saved.items():
            (self.folder/name).write_text(json.dumps(value))

    def run_audit(self):
        with patch.object(p,"followup_audit",return_value=self.parent):
            return p.audit(self.folder)

    def test_original_provider_candidates_and_populator_callers(self):
        report=self.run_audit()
        self.assertEqual(len(report["supplierAndSetupCandidates"]),3)
        self.assertEqual(report["supplierAndSetupCandidates"][0]["requestedAddress"],"0x53b0")
        self.assertEqual(report["supplierAndSetupCandidates"][1]["requestedAddress"],"0x23b0")
        self.assertEqual(report["supplierAndSetupCandidates"][2]["requestedAddress"],"0x20ac")
        self.assertEqual(report["ramTableCallerXrefs"]["count"],2)
        self.assertEqual(report["ramTableCallerXrefs"]["callsiteAddresses"],
                         ["0x2340","0x234c"])

    def test_static_fallback_cannot_be_promoted_to_live_kernel_address(self):
        report=self.run_audit()
        self.assertEqual(report["observedFallbackOnly"]["fieldAtDAT_0000d6f8"],
                         "0x80000000")
        for key in ("efiRamProtocolRegistrationProven",
                    "getRamPartitionsCallbackProven","numericRuntimeRamBaseMeasured",
                    "kernelPhysicalEntryVerified","phoneModified"):
            self.assertFalse(report[key])
        self.assertIn("NOT a measured RAM partition",p.markdown(report))

    def test_unverified_parent_function_digest_rejected(self):
        self.parent["originalEnvDxeSha256"]="0"*64
        with self.assertRaisesRegex(ExtractionError,"provenance"):
            self.run_audit()

    def test_missing_verified_parent_call_rejected(self):
        self.parent["functionDossiers"][2]["pseudocode"]="FUN_00005430();"
        with self.assertRaisesRegex(ExtractionError,"data/callsite evidence changed"):
            self.run_audit()

    def test_no_forged_efi_registration_in_prior_evidence(self):
        self.parent["protocolRegistrationSiteConfirmed"]=True
        with self.assertRaisesRegex(ExtractionError,"incorrectly promoted"):
            self.run_audit()

    def test_unexpected_fallback_data_refused(self):
        self.parent["functionDossiers"][2]["pseudocode"] = (
            self.parent["functionDossiers"][2]["pseudocode"]
            .replace("0x60000000","0x70000000"))
        with self.assertRaisesRegex(ExtractionError,"data/callsite evidence changed"):
            self.run_audit()

    def test_wrong_ghidra_function_request_rejected(self):
        item="rea-envdxe-input-trace-table-input-provider.json"
        self.saved[item]["parameters"]["procedure"]="0x5200"
        self.write()
        with self.assertRaisesRegex(ExtractionError,"Wrong EnvDxe"):
            self.run_audit()

    def test_wrong_ghidra_function_sha_rejected(self):
        item="rea-envdxe-input-trace-init-protocol-candidate.json"
        self.saved[item]["subject"]["digest"]["sha256"]="0"*64
        self.write()
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.run_audit()

    def test_function_address_must_be_inside_ghidra_body(self):
        item="rea-envdxe-input-trace-init-services-candidate.json"
        self.saved[item]["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x9000","end":"0x9100"}]
        self.write()
        with self.assertRaisesRegex(ExtractionError,"not inside"):
            self.run_audit()

    def test_untrusted_ghidra_pseudocode_not_accepted(self):
        item="rea-envdxe-input-trace-table-input-provider.json"
        self.saved[item]["normalized_result"]["pseudocode"]=""
        self.write()
        with self.assertRaisesRegex(ExtractionError,"missing/oversized"):
            self.run_audit()

    def test_false_pcode_availability_not_hidden(self):
        item="rea-envdxe-input-trace-table-input-provider.json"
        self.saved[item]["normalized_result"]["native_value_flow"]["available"]=False
        self.write()
        self.assertFalse(self.run_audit()["supplierAndSetupCandidates"][0]["highFunctionAvailable"])

    def test_genuine_zero_xrefs_is_not_absence_of_callers(self):
        item="rea-envdxe-input-trace-"+p.XREF_LABEL+".json"
        self.saved[item]["normalized_result"]=[]
        self.write()
        outcome=self.run_audit()
        self.assertEqual(outcome["ramTableCallerXrefs"]["count"],0)
        self.assertIn("does not prove the routine unreachable",p.markdown(outcome))

    def test_foreign_xref_target_refused(self):
        item="rea-envdxe-input-trace-"+p.XREF_LABEL+".json"
        self.saved[item]["parameters"]["address"]="0x5430"
        self.write()
        with self.assertRaisesRegex(ExtractionError,"not queried at verified"):
            self.run_audit()

    def test_invalid_xref_coordinate_refused(self):
        item="rea-envdxe-input-trace-"+p.XREF_LABEL+".json"
        self.saved[item]["normalized_result"]=["0x1234;rm"]
        self.write()
        with self.assertRaisesRegex(ExtractionError,"Non-static"):
            self.run_audit()

    def test_duplicate_xrefs_deduplicated_but_actual_count_preserved(self):
        item="rea-envdxe-input-trace-"+p.XREF_LABEL+".json"
        self.saved[item]["normalized_result"]=["0x2340","0x2340"]
        self.write()
        got=self.run_audit()["ramTableCallerXrefs"]
        self.assertEqual(got["count"],2)
        self.assertEqual(got["callsiteAddresses"],["0x2340"])

    def test_symlink_evidence_refused(self):
        name="rea-envdxe-input-trace-table-input-provider.json"
        path=self.folder/name
        linked=self.folder/"real-evidence.json"
        linked.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(linked)
        with self.assertRaisesRegex(ExtractionError,"missing"):
            self.run_audit()


if __name__ == "__main__":
    unittest.main()
