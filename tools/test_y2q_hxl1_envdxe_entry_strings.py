#!/usr/bin/env python3
"""Synthetic original-EnvDxe Ghidra entry and targeted-string regressions."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_entry_strings as impl
from tools.y2q_hxl1_extract_envdxe import ExtractionError


class EnvDxeEntrypointStringEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.guid_baseline={
            "referenceCount":0, "importedGuidBytesVerified":True,
            "guidByteReadbackEvidenceId":"ev_readback",
            "evidenceId":"ev_guid_0",
        }
        self.entry={
            "operation":"analyze_function",
            "provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":impl.PE_SHA256},"architecture":"arm64"},
            "parameters":{"procedure":"0x1000"},
            "evidence_id":"ev_entry",
            "normalized_result":{
                "procedure":{
                    "address":"0x1000","name":"FUN_00001000",
                    "body":{
                        "available":True,
                        "provenance":"ghidra-function-body-address-set",
                        "ranges":[{"start":"0x1000","end":"0x1320"}],
                    },
                },
                "pseudocode":"void FUN_00001000(void) { FUN_00001800(); }",
                "native_value_flow":{"available":True},
                "callers":[],"callees":["0x1800"],
            },
        }
        self.write("rea-envdxe-entry-function.json", self.entry)
        for label,pattern in impl.QUERIES:
            self.write("rea-envdxe-search-"+label+".json",{
                "operation":"search_strings",
                "provider":{"id":"ghidra"},
                "subject":{"digest":{"sha256":impl.PE_SHA256},"architecture":"arm64"},
                "parameters":{"pattern":pattern,"mode":"literal","case_sensitive":False},
                "evidence_id":"ev_search_"+label,
                "normalized_result":[{"address":"0x8000","value":pattern+" failed"}],
            })

    def write(self,name,data):
        (self.folder/name).write_text(json.dumps(data))

    def run_audit(self):
        with patch.object(impl,"xref_info",return_value=self.guid_baseline):
            with patch.object(impl,"entry_address",return_value="0x1000"):
                return impl.analyze(self.folder)

    def test_exact_original_entry_and_three_strings_authenticated(self):
        result=self.run_audit()
        self.assertEqual(result["entryFunction"]["requestedEntryAddress"],"0x1000")
        self.assertEqual(result["entryFunction"]["containingFunctionEntry"],"0x1000")
        self.assertEqual(len(result["stringSearches"]),3)
        self.assertTrue(all(x["hitCount"]==1 for x in result["stringSearches"]))
        self.assertFalse(result["protocolRegistrationFunctionProved"])
        self.assertFalse(result["actualFirmwareRamPartitionsRead"])
        self.assertFalse(result["deviceModified"])

    def test_no_guid_xref_is_a_required_factual_precondition(self):
        self.guid_baseline["referenceCount"]=1
        with self.assertRaisesRegex(ExtractionError,"verified zero-xref"):
            self.run_audit()

    def test_original_pe_hash_mismatch_in_entry_rejected(self):
        self.entry["subject"]["digest"]["sha256"]="0"*64
        self.write("rea-envdxe-entry-function.json",self.entry)
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.run_audit()

    def test_incorrect_entrypoint_query_rejected(self):
        self.entry["parameters"]["procedure"]="0x2000"
        self.write("rea-envdxe-entry-function.json",self.entry)
        with self.assertRaisesRegex(ExtractionError,"not actual PE entry"):
            self.run_audit()

    def test_query_address_must_be_inside_ghidra_body(self):
        self.entry["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x3000","end":"0x3110"}]
        self.write("rea-envdxe-entry-function.json",self.entry)
        with self.assertRaisesRegex(ExtractionError,"not contained"):
            self.run_audit()

    def test_empty_string_search_is_valid_negative_evidence(self):
        self.write("rea-envdxe-search-ram-partition.json",{
            "operation":"search_strings","provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":impl.PE_SHA256},"architecture":"arm64"},
            "parameters":{"pattern":"RamPartition","mode":"literal","case_sensitive":False},
            "normalized_result":[],"evidence_id":"ev_empty",
        })
        result=self.run_audit()
        self.assertEqual(result["stringSearches"][0]["hitCount"],0)
        self.assertFalse(result["getRamPartitionsImplementationProved"])

    def test_wrong_search_literal_rejected(self):
        got=json.loads((self.folder/"rea-envdxe-search-env-driver.json").read_text())
        got["parameters"]["pattern"]="KernelBase"
        self.write("rea-envdxe-search-env-driver.json",got)
        with self.assertRaisesRegex(ExtractionError,"query operation"):
            self.run_audit()

    def test_invalid_ghidra_string_coordinate_rejected(self):
        got=json.loads((self.folder/"rea-envdxe-search-get-ram-partitions.json").read_text())
        got["normalized_result"][0]["address"]="0x100;evil"
        self.write("rea-envdxe-search-get-ram-partitions.json",got)
        with self.assertRaisesRegex(ExtractionError,"Invalid Ghidra string"):
            self.run_audit()

    def test_wrong_search_result_does_not_pretend_match(self):
        got=json.loads((self.folder/"rea-envdxe-search-env-driver.json").read_text())
        got["normalized_result"][0]["value"]="Other firmware"
        self.write("rea-envdxe-search-env-driver.json",got)
        with self.assertRaisesRegex(ExtractionError,"did not match"):
            self.run_audit()

    def test_no_missing_entry_pcode_field_promoted_to_verified(self):
        self.entry["normalized_result"].pop("native_value_flow")
        self.write("rea-envdxe-entry-function.json",self.entry)
        with self.assertRaisesRegex(ExtractionError,"p-code"):
            self.run_audit()

    def test_entry_address_uses_pinned_pe_header_metadata(self):
        header={"preferredImageBase":"0x0","entryPointRva":"0x1000"}
        manifest={"peInfo":header}
        (self.folder/"original-envdxe-hxl1.json").write_text(json.dumps(manifest))
        with patch.object(impl,"source_info",return_value={
                "efiFile":str(self.folder/"original.efi"),
                "preferredAddress":"0xd118"}):
            (self.folder/"original.efi").write_bytes(b"synthetic")
            with patch.object(impl,"identify_pe",return_value=header):
                self.assertEqual(impl.entry_address(self.folder),"0x1000")

    def test_pe_entry_manifest_mismatch_rejected(self):
        (self.folder/"original-envdxe-hxl1.json").write_text(
            json.dumps({"peInfo":{"preferredImageBase":"0x0","entryPointRva":"0x2000"}}))
        with patch.object(impl,"source_info",return_value={
                "efiFile":str(self.folder/"orig.efi"),
                "preferredAddress":"0xd118"}):
            (self.folder/"orig.efi").write_bytes(b"synthetic")
            with patch.object(impl,"identify_pe",return_value={
                    "preferredImageBase":"0x0","entryPointRva":"0x1000"}):
                with self.assertRaisesRegex(ExtractionError,"differs"):
                    impl.entry_address(self.folder)

    def test_summary_keeps_static_only_boundary(self):
        doc=impl.render(self.run_audit())
        self.assertIn("not a substitute for actual Samsung code",doc)
        self.assertIn("No runtime DRAM values",doc)


if __name__=="__main__":
    unittest.main()
