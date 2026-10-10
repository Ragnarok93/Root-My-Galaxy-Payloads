#!/usr/bin/env python3
"""Synthetic failure gates: HXL1 EnvDxe SMEM402 and protocol GUID identity."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_smem402_protocol as impl
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def parent():
    return {
        "originalEnvDxeSha256":impl.PE_SHA256,
        "efiRamProtocolRegistrationProven":False,
        "supplierAndSetupCandidates":[
            {"label":"table-input-provider","functionEntry":"0x53b0",
             "evidenceId":"ev_smem402",
             "pseudocode":"pi=FUN_00007d08(a,0x192,b);\nFUN_00005288(pi,fmt);"},
            {"label":"init-protocol-candidate","functionEntry":"0x23b0",
             "evidenceId":"ev_init_proto",
             "pseudocode":
                 "return (**(code **)(DAT_0000d328 + 0x80))("
                 "handle,&DAT_0000d2e8,&DAT_0000d178,0);"},
            {"label":"init-services-candidate","functionEntry":"0x20ac",
             "evidenceId":"ev_services","pseudocode":"FUN_00004ecc();"},
        ],
        "ramTableCallerXrefs":{
            "requestedAddress":"0x5560","count":1,
            "callsiteAddresses":["0x2064"],
            "evidenceId":"ev_populator_call",
        },
    }


def function_record(label,address):
    return {
        "operation":"analyze_function","provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":impl.PE_SHA256},"architecture":"arm64"},
        "parameters":{"procedure":address},"evidence_id":"ev_"+label,
        "normalized_result":{
            "procedure":{
                "address":hex(int(address,16)-4),
                "name":"FUN_"+address.removeprefix("0x").zfill(8),
                "body":{
                    "available":True,
                    "provenance":"ghidra-function-body-address-set",
                    "ranges":[{"start":hex(int(address,16)-4),
                               "end":hex(int(address,16)+48)}],
                },
            },
            "native_value_flow":{"available":True},
            "pseudocode":"undefined8 foo(void) { FUN_00005288(); return 0; }",
        },
    }


class Hxl1Smem402ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.source=parent()
        self.guid={
            "operation":"read_bytes","provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":impl.PE_SHA256},"architecture":"arm64"},
            "parameters":{"address":impl.GUID_AT,"length":16},
            "normalized_result":{
                "address":impl.GUID_AT,
                "requested_bytes":16,"returned_bytes":16,
                "complete":True,
                "bytes_hex":"00112233445566778899aabbccddeeff",
            },
            "evidence_id":"ev_another_protocol_guid",
        }
        self.files={impl.GUID_FILE:self.guid}
        for label,address in impl.FUNCTIONS:
            self.files["rea-envdxe-ram-source-verify-"+label+".json"]=function_record(label,address)
        self.persist()

    def persist(self):
        for name,obj in self.files.items():
            (self.folder/name).write_text(json.dumps(obj))

    def audit(self):
        with patch.object(impl,"input_audit",return_value=self.source):
            return impl.audit(self.folder)

    def test_original_smem402_guid_and_three_followup_functions(self):
        result=self.audit()
        self.assertEqual(result["smemItemIdentifier"]["decimal"],402)
        self.assertEqual(len(result["originalSourceFunctions"]),3)
        self.assertEqual(result["originalSourceFunctions"][0]["queriedAddress"],"0x2064")
        self.assertEqual(result["originalCandidateInstallationGuid"]["matchesKnownRamPartitionGuid"],False)
        self.assertFalse(result["efiRamProtocolRegistrationProven"])
        self.assertFalse(result["kernelPhysicalLoadVerified"])
        self.assertFalse(result["deviceModified"])

    def test_true_ram_protocol_guid_is_classified_but_not_registration(self):
        self.guid["normalized_result"]["bytes_hex"]=impl.GUID_LE.hex()
        self.persist()
        report=self.audit()
        self.assertTrue(report["originalCandidateInstallationGuid"]["matchesKnownRamPartitionGuid"])
        self.assertFalse(report["efiRamProtocolRegistrationProven"])

    def test_actual_original_0x192_call_must_be_present(self):
        self.source["supplierAndSetupCandidates"][0]["pseudocode"] = "FUN_00007d08(0x193);"
        with self.assertRaisesRegex(ExtractionError,"0x192 SMEM"):
            self.audit()

    def test_wrong_d2e8_registration_pseudocode_rejected(self):
        self.source["supplierAndSetupCandidates"][1]["pseudocode"]="return 0;"
        with self.assertRaisesRegex(ExtractionError,"service table"):
            self.audit()

    def test_missing_original_ram_populator_caller_rejected(self):
        self.source["ramTableCallerXrefs"]["callsiteAddresses"]=[]
        with self.assertRaisesRegex(ExtractionError,"0x2064"):
            self.audit()

    def test_mismatched_parent_sha_rejected(self):
        self.source["originalEnvDxeSha256"]="0"*64
        with self.assertRaisesRegex(ExtractionError,"parent SHA256"):
            self.audit()

    def test_existing_unverified_registration_must_remain_false(self):
        self.source["efiRamProtocolRegistrationProven"]=True
        with self.assertRaisesRegex(ExtractionError,"incorrectly claims"):
            self.audit()

    def test_genuine_other_guid_read_exact_coordinate_required(self):
        self.guid["parameters"]["address"]="0xd118"
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"wrong target"):
            self.audit()

    def test_partial_guid_read_rejected(self):
        self.guid["normalized_result"]["returned_bytes"]=15
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"incomplete"):
            self.audit()

    def test_wrong_original_firmware_sha_rejected(self):
        self.guid["subject"]["digest"]["sha256"]="0"*64
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.audit()

    def test_original_function_request_provenance_rejected(self):
        key="rea-envdxe-ram-source-verify-ram-table-initializer-caller.json"
        self.files[key]["parameters"]["procedure"]="0x2060"
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"Incorrect Ghidra"):
            self.audit()

    def test_0x2064_must_be_in_owning_function_body(self):
        key="rea-envdxe-ram-source-verify-ram-table-initializer-caller.json"
        self.files[key]["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x1000","end":"0x1100"}]
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"outside Ghidra"):
            self.audit()

    def test_no_fabricated_pseudocode_when_unavailable(self):
        key="rea-envdxe-ram-source-verify-smem-item-accessor.json"
        self.files[key]["normalized_result"]["pseudocode"]=""
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"code missing"):
            self.audit()

    def test_no_claim_when_indirect_reference_is_all_we_have(self):
        report=self.audit()
        text=impl.render(report)
        self.assertIn("DOES NOT directly pass",text)
        self.assertIn("No boot-time SMEM data",text)


if __name__=="__main__":
    unittest.main()
