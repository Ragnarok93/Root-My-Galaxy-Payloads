#!/usr/bin/env python3
"""Synthetic REA xref provenance fixtures for exact original EnvDxe GUID."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_rea_xrefs as audit
from tools.y2q_hxl1_extract_envdxe import ExtractionError


class OriginalEnvDxeXrefsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.pe=bytearray(audit.GUID_PE_FILE_OFFSET+16)
        self.pe[audit.GUID_PE_FILE_OFFSET:]=audit.GUID_LE
        self.sha=hashlib.sha256(self.pe).hexdigest()
        (self.folder/audit.OUT_NAME).write_bytes(self.pe)
        self.manifest={
            "xblSha256":audit.XBL_SHA256,
            "originalEnvDxePeSha256":self.sha,
            "ffsGuid":audit.FILE_GUID,
            "ui":"EnvDxe",
            "guidPeFileOffset":hex(audit.GUID_PE_FILE_OFFSET),
            "guidPosition":{"guidRva":"0xe118",
                            "preferredImageVirtualAddress":"0xe118"}
        }
        self.write_manifest()
        self.readback={
            "operation":"read_bytes",
            "provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":self.sha},"architecture":"arm64"},
            "parameters":{"address":"0xe118","length":16},
            "normalized_result":{
                "address":"0xe118","requested_bytes":16,
                "returned_bytes":16,"complete":True,
                "bytes_hex":audit.GUID_LE.hex(),
            },
            "evidence_id":"ev_original_readback",
        }
        self.write_readback()
        self.evidence={
            "operation":"xrefs",
            "provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":self.sha},"architecture":"arm64"},
            "parameters":{"address":"0xe118"},
            "normalized_result":["0x15320","0x15330"],
            "evidence_id":"ev_exact_original_test",
        }
        self.write_evidence()

    def write_manifest(self):
        (self.folder/"original-envdxe-hxl1.json").write_text(json.dumps(self.manifest))

    def write_evidence(self):
        (self.folder/audit.XREF_NAME).write_text(json.dumps(self.evidence))

    def write_readback(self):
        (self.folder/audit.READBACK_NAME).write_text(json.dumps(self.readback))

    def verify(self):
        with patch.object(audit,"PE_SHA256",self.sha):
            return audit.xref_info(self.folder)

    def test_original_guid_xrefs_and_source_count(self):
        result=self.verify()
        self.assertEqual(result["referenceCount"],2)
        self.assertEqual(result["distinctSourceReferences"],["0x15320","0x15330"])
        self.assertEqual(result["evidenceId"],"ev_exact_original_test")
        self.assertFalse(result["protocolInstallCallIdentified"])
        self.assertFalse(result["actualKernelPhysicalAddressVerified"])
        self.assertFalse(result["deviceModified"])

    def test_repeated_xrefs_are_deduplicated_without_losing_count(self):
        self.evidence["normalized_result"]=["0x15320","0x15320"]
        self.write_evidence()
        result=self.verify()
        self.assertEqual(result["referenceCount"],2)
        self.assertEqual(result["distinctSourceReferences"],["0x15320"])

    def test_empty_xrefs_is_valid_but_not_implementation_absence(self):
        self.evidence["normalized_result"]=[]
        self.write_evidence()
        result=self.verify()
        self.assertEqual(result["referenceCount"],0)
        self.assertIn("not proof",audit.report_text(result))

    def test_wrong_original_pe_sha_rejected(self):
        self.evidence["subject"]["digest"]["sha256"]="0"*64
        self.write_evidence()
        with self.assertRaisesRegex(ExtractionError,"not for exact"):
            self.verify()

    def test_guid_target_query_address_rejected(self):
        self.evidence["parameters"]["address"]="0xd118"
        self.write_evidence()
        with self.assertRaisesRegex(ExtractionError,"mapped GUID"):
            self.verify()

    def test_forged_reference_address_rejected(self):
        self.evidence["normalized_result"]=["0x15320;rm"]
        self.write_evidence()
        with self.assertRaisesRegex(ExtractionError,"Bad Ghidra"):
            self.verify()

    def test_mismatched_original_manifest_refused(self):
        self.manifest["ffsGuid"]="00000000-0000-0000-0000-000000000000"
        self.write_manifest()
        with self.assertRaisesRegex(ExtractionError,"manifest provenance"):
            self.verify()

    def test_modified_pe_refused_even_when_manifest_exists(self):
        self.pe[0]^=1
        (self.folder/audit.OUT_NAME).write_bytes(self.pe)
        with self.assertRaisesRegex(ExtractionError,"bytes, SHA256"):
            self.verify()

    def test_rea_readback_is_byte_verified_before_xrefs(self):
        result=self.verify()
        self.assertTrue(result["importedGuidBytesVerified"])
        self.assertEqual(result["guidByteReadbackEvidenceId"],"ev_original_readback")

    def test_import_address_mismatch_is_a_hard_stop(self):
        self.readback["normalized_result"]["bytes_hex"]="00"*16
        self.write_readback()
        with self.assertRaisesRegex(ExtractionError,"image base"):
            self.verify()

    def test_missing_import_readback_never_promotes_xrefs(self):
        (self.folder/audit.READBACK_NAME).unlink()
        with self.assertRaisesRegex(ExtractionError,"Evidence absent"):
            self.verify()

    def test_foreign_readback_provider_rejected(self):
        self.readback["provider"]["id"]="hopper"
        self.write_readback()
        with self.assertRaisesRegex(ExtractionError,"provenance mismatch"):
            self.verify()

    def test_guid_must_map_to_pe_section(self):
        self.manifest["guidPosition"]=None
        self.write_manifest()
        with self.assertRaisesRegex(ExtractionError,"does not map"):
            self.verify()


if __name__=="__main__":
    unittest.main()
