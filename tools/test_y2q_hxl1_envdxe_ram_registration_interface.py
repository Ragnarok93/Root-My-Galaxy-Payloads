#!/usr/bin/env python3
"""20 independent ABI, identity, interface and conditional-gate regressions."""
from __future__ import annotations
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_ram_registration_callback as mod
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def initial_prior():
    return {
        "originalEnvDxeSha256":mod.PE_SHA256,
        "efiRamProtocolRegistrationProven":False,
        "numericRuntimeRamBaseMeasured":False,
        "kernelPhysicalLoadVerified":False,
        "smemItemIdentifier":{"decimal":402},
        "originalCandidateInstallationGuid":{
            "staticAddress":"0xd2e8",
            "originalBytesHex":"00"*16,
            "matchesKnownRamPartitionGuid":False,
            "readbackEvidenceId":"ev_zero_guid",
        },
        "originalSourceFunctions":[{
            "label":"ram-table-initializer-caller",
            "queriedAddress":"0x2064",
            "functionEntry":"0x205c",
            "originalEvidenceId":"ev_205c",
            "originalPseudocode":(
                "lVar1 = FUN_00005560(params);\n"
                "if (lVar1 != 0) { return 0x8000000000000003; }\n"
                "uVar2 = (**(code **)(DAT_0000d328 + 0x148))"
                "(0xd2b8,0xd118,0xd1d0,0,0);\n"
            ),
        }]
    }


def item_record(words=(0,0,0,0x3420,0,0)):
    return {
        "operation":"read_bytes",
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":mod.PE_SHA256},"architecture":"arm64"},
        "parameters":{"address":mod.PROTOCOL_INTERFACE_ADDR,
                      "length":mod.INTERFACE_LENGTH},
        "evidence_id":"ev_interface_48",
        "normalized_result":{
            "address":mod.PROTOCOL_INTERFACE_ADDR,
            "requested_bytes":48,
            "returned_bytes":48,
            "complete":True,
            "bytes_hex":struct.pack("<6Q",*words).hex(),
        },
    }


class RegistrationInterfaceFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.previous=initial_prior()
        self.interface=item_record()
        self.persist()

    def persist(self):
        (self.folder/mod.READ_EVIDENCE).write_text(json.dumps(self.interface))

    def reg(self):
        with patch.object(mod,"prior_audit",return_value=self.previous):
            return mod.original_registration(self.folder)

    def read(self):
        return mod.interface_readback(self.folder)

    def test_static_registration_shape_matches_verified_abi(self):
        result=self.reg()
        self.assertEqual(result["bootServicesMethodOffset"],"0x148")
        self.assertEqual(result["guidSourceStaticAddress"],"0xd118")
        self.assertEqual(result["interfaceStaticAddress"],"0xd1d0")
        self.assertTrue(result["uefiAbiConsistentInstallMultipleProtocolInterfaces"])

    def test_registration_is_conditional_not_observed_live(self):
        result=self.reg()
        self.assertTrue(result["calledAfterTableInitReturnsSuccess"])
        self.assertFalse(result["registeredSuccessfullyAtBoot"])
        self.assertFalse(result["bootServicesPointerProvenFromRuntime"])

    def test_zero_guid_branch_does_not_become_ram_protocol(self):
        result=self.reg()
        self.assertEqual(result["zeroGuidOtherCallSite"],"0xd2e8")
        self.assertEqual(result["otherZeroGuidEvidenceId"],"ev_zero_guid")

    def test_missing_rampartition_initializer_call_refused(self):
        self.previous["originalSourceFunctions"][0]["originalPseudocode"] = (
            self.previous["originalSourceFunctions"][0]["originalPseudocode"]
            .replace("FUN_00005560(","FUN_00005564("))
        with self.assertRaisesRegex(ExtractionError,"callsite"):
            self.reg()

    def test_missing_success_guard_refused(self):
        self.previous["originalSourceFunctions"][0]["originalPseudocode"] = (
            self.previous["originalSourceFunctions"][0]["originalPseudocode"]
            .replace("if (lVar1 != 0)","if (lVar1 == 0)"))
        with self.assertRaisesRegex(ExtractionError,"callsite"):
            self.reg()

    def test_wrong_boot_services_method_offset_refused(self):
        self.previous["originalSourceFunctions"][0]["originalPseudocode"] = (
            self.previous["originalSourceFunctions"][0]["originalPseudocode"]
            .replace("0x148","0x80"))
        with self.assertRaisesRegex(ExtractionError,"callsite"):
            self.reg()

    def test_wrong_guid_constant_refused(self):
        self.previous["originalSourceFunctions"][0]["originalPseudocode"] = (
            self.previous["originalSourceFunctions"][0]["originalPseudocode"]
            .replace("0xd118","0xd2e8"))
        with self.assertRaisesRegex(ExtractionError,"callsite"):
            self.reg()

    def test_wrong_interface_constant_refused(self):
        self.previous["originalSourceFunctions"][0]["originalPseudocode"] = (
            self.previous["originalSourceFunctions"][0]["originalPseudocode"]
            .replace("0xd1d0","0xd118"))
        with self.assertRaisesRegex(ExtractionError,"callsite"):
            self.reg()

    def test_wrong_original_envdxe_pe_sha_refused(self):
        self.previous["originalEnvDxeSha256"]="0"*64
        with self.assertRaisesRegex(ExtractionError,"SHA256"):
            self.reg()

    def test_previous_evidence_must_not_claim_runtime_ram_base(self):
        self.previous["numericRuntimeRamBaseMeasured"]=True
        with self.assertRaisesRegex(ExtractionError,"without runtime"):
            self.reg()

    def test_previous_evidence_must_not_claim_registered_at_boot(self):
        self.previous["efiRamProtocolRegistrationProven"]=True
        with self.assertRaisesRegex(ExtractionError,"without runtime"):
            self.reg()

    def test_wrong_smem_item_dependency_refused(self):
        self.previous["smemItemIdentifier"]["decimal"]=403
        with self.assertRaisesRegex(ExtractionError,"402"):
            self.reg()

    def test_missing_initializer_function_refused(self):
        self.previous["originalSourceFunctions"]=[]
        with self.assertRaisesRegex(ExtractionError,"exactly one"):
            self.reg()

    def test_duplicate_initializer_function_refused(self):
        self.previous["originalSourceFunctions"]*=2
        with self.assertRaisesRegex(ExtractionError,"exactly one"):
            self.reg()

    def test_different_original_guid_bytes_not_misidentified(self):
        self.previous["originalCandidateInstallationGuid"]["originalBytesHex"]="11"*16
        with self.assertRaisesRegex(ExtractionError,"zero-GUID"):
            self.reg()

    def test_exact_48_byte_protocol_interface_read(self):
        item=self.read()
        self.assertEqual(item["sourceStaticAddress"],"0xd1d0")
        self.assertEqual(item["getRamPartitionsSlotStaticAddress"],"0xd1e8")
        self.assertEqual(item["getRamPartitionsOffset"],"0x18")
        self.assertEqual(item["getRamPartitionsSlotRawQword"],"0x3420")
        self.assertEqual(item["unrelocatedStaticFunctionCoordinateCandidate"],"0x3420")

    def test_endianness_of_six_pointer_slots(self):
        self.interface=item_record((0x1122334455667788,2,3,0x12345678,5,6))
        self.persist()
        item=self.read()
        self.assertEqual(item["qwordsHex"][0],"0x1122334455667788")
        self.assertEqual(item["getRamPartitionsSlotRawQword"],"0x12345678")

    def test_zero_uninitialized_callback_is_not_false_absence(self):
        self.interface=item_record((0,0,0,0,0,0))
        self.persist()
        item=self.read()
        self.assertIsNone(item["unrelocatedStaticFunctionCoordinateCandidate"])
        self.assertTrue(item["callbackMayRequireRelocationsOrRuntimeInitialization"])
        self.assertFalse(item["actualRuntimeCallbackPointerRead"])

    def test_misaligned_callback_rejected_as_code_coordinate(self):
        self.interface=item_record((0,0,0,0x3421,0,0))
        self.persist()
        self.assertIsNone(self.read()["unrelocatedStaticFunctionCoordinateCandidate"])

    def test_truncated_interface_read_refused(self):
        self.interface["normalized_result"]["returned_bytes"]=47
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"incomplete"):
            self.read()

    def test_changed_48_byte_target_refused(self):
        self.interface["parameters"]["address"]="0xd118"
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"0xd1d0"):
            self.read()

    def test_foreign_firmware_sha_in_interface_read_rejected(self):
        self.interface["subject"]["digest"]["sha256"]="0"*64
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.read()

    def test_symlinked_interface_evidence_refused(self):
        original=self.folder/mod.READ_EVIDENCE
        actual=self.folder/"copied.json"
        actual.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(actual)
        with self.assertRaisesRegex(ExtractionError,"missing"):
            self.read()


if __name__=="__main__":
    unittest.main()
