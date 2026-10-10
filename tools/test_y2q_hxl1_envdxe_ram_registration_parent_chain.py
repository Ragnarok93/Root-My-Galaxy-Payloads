#!/usr/bin/env python3
"""Integration contract: REAL upstream SMEM402.audit -> RAM installer check.

We deliberately do not mock the immediate parent's complete report. This
reproduces the stage-boundary mismatch that passed 45 isolated fixtures but
failed for the owner's exact, verified stock EnvDxe REA evidence.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_smem402_protocol as upstream
from tools import y2q_hxl1_envdxe_ram_registration_callback as downstream
from tools.test_y2q_hxl1_envdxe_smem402_protocol import (
    Hxl1Smem402ProtocolTests,
)
from tools.y2q_hxl1_extract_envdxe import ExtractionError


ORIGINAL_GHIDRA_205C=(
    "lVar1 = FUN_00005560(a,b,c);\n"
    "if (lVar1 != 0) { return 0x8000000000000003; }\n"
    "uVar2 = (**(code **)(DAT_0000d328 + 0x148))"
    "(0xd2b8,0xd118,0xd1d0,0,0);\n"
)


class RealUpstreamContractTests(unittest.TestCase):
    def setUp(self):
        # Reuse upstream's real three-function and GUID evidence fixtures.
        # Patching only the earlier input-table parent deliberately exercises
        # every nontrivial function in the immediately preceding stage.
        self.up=Hxl1Smem402ProtocolTests(
            "test_original_smem402_guid_and_three_followup_functions")
        self.up.setUp()
        self.addCleanup(self.up.doCleanups)
        self.up.guid["normalized_result"]["bytes_hex"]="00"*16
        key="rea-envdxe-ram-source-verify-ram-table-initializer-caller.json"
        record=self.up.files[key]["normalized_result"]
        record["procedure"]["address"]="0x205c"
        record["procedure"]["body"]["ranges"]=[
            {"start":"0x205c","end":"0x2094"}
        ]
        record["pseudocode"]=ORIGINAL_GHIDRA_205C
        self.up.persist()

    def immediate_upstream(self):
        with patch.object(upstream,"input_audit",return_value=self.up.source):
            return upstream.audit(self.up.folder)

    def downstream(self):
        with patch.object(downstream,"prior_audit",side_effect=lambda _:self.immediate_upstream()):
            return downstream.original_registration(self.up.folder)

    def test_true_previous_audit_runs_before_conditional_registration(self):
        parent=self.immediate_upstream()
        self.assertEqual(parent["originalEnvDxeSha256"],downstream.PE_SHA256)
        self.assertEqual(parent["smemItemIdentifier"]["decimal"],402)
        self.assertEqual(parent["originalCandidateInstallationGuid"]["originalBytesHex"],"00"*16)
        self.assertEqual(parent["originalSourceFunctions"][0]["functionEntry"],"0x205c")
        result=self.downstream()
        self.assertEqual(result["originalCallerAt"],"0x205c")
        self.assertTrue(result["uefiAbiConsistentInstallMultipleProtocolInterfaces"])
        self.assertFalse(result["registeredSuccessfullyAtBoot"])

    def test_real_upstream_contract_does_not_expose_earlier_stage_ram_flag(self):
        actual=self.immediate_upstream()
        self.assertNotIn("numericRuntimeRamBaseMeasured",actual)
        self.assertIn("physicalBaseMemoryMeasured",actual)
        self.assertIs(actual["physicalBaseMemoryMeasured"],False)
        self.assertEqual(self.downstream()["interfaceStaticAddress"],"0xd1d0")

    def test_mutated_immediate_parent_registration_flag_refused(self):
        original=upstream.audit
        def tamper(folder):
            with patch.object(upstream,"input_audit",return_value=self.up.source):
                record=original(folder)
            record["efiRamProtocolRegistrationProven"]=True
            return record
        with patch.object(downstream,"prior_audit",side_effect=tamper):
            with self.assertRaisesRegex(ExtractionError,"without runtime"):
                downstream.original_registration(self.up.folder)

    def test_mutated_immediate_parent_memory_flag_refused(self):
        original=upstream.audit
        def tamper(folder):
            with patch.object(upstream,"input_audit",return_value=self.up.source):
                record=original(folder)
            record["physicalBaseMemoryMeasured"]=True
            return record
        with patch.object(downstream,"prior_audit",side_effect=tamper):
            with self.assertRaisesRegex(ExtractionError,"without runtime"):
                downstream.original_registration(self.up.folder)

    def test_missing_immediate_parent_memory_field_refused(self):
        original=upstream.audit
        def tamper(folder):
            with patch.object(upstream,"input_audit",return_value=self.up.source):
                record=original(folder)
            record.pop("physicalBaseMemoryMeasured")
            return record
        with patch.object(downstream,"prior_audit",side_effect=tamper):
            with self.assertRaisesRegex(ExtractionError,"schema missing field: physicalBaseMemoryMeasured"):
                downstream.original_registration(self.up.folder)

    def test_bad_genuine_provider_pseudocode_fails_from_real_chain(self):
        key="rea-envdxe-ram-source-verify-ram-table-initializer-caller.json"
        self.up.files[key]["normalized_result"]["pseudocode"] = (
            ORIGINAL_GHIDRA_205C.replace("0x148","0x80")
        )
        self.up.persist()
        with self.assertRaisesRegex(ExtractionError,"registration callsite"):
            self.downstream()

    def test_bad_real_qualcomm_smem_identifier_fails_before_registration(self):
        self.up.source["ramTableCallerXrefs"]["count"]=0
        with self.assertRaisesRegex(ExtractionError,"sole Ghidra populator"):
            self.downstream()

    def test_wrong_upstream_extracted_firmware_sha_refused_before_registration(self):
        self.up.files["rea-envdxe-ram-source-verify-ram-table-initializer-caller.json"][
            "subject"]["digest"]["sha256"]="0"*64
        self.up.persist()
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.downstream()


if __name__=="__main__":
    unittest.main()
