#!/usr/bin/env python3
"""Synthetic binary-section and Ghidra proof for actual EnvDxe callback code."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_callback_raw_proof as impl
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def pe_with_executable_section():
    pe=bytearray(0x2000)
    pe[0:2]=b"MZ"
    struct.pack_into("<I",pe,0x3c,0x80)
    nt=0x80
    pe[nt:nt+4]=b"PE\x00\x00"
    struct.pack_into("<H",pe,nt+6,1)
    struct.pack_into("<H",pe,nt+20,0xf0)
    sec=nt+24+0xf0
    pe[sec:sec+8]=b".text\x00\x00\x00"
    struct.pack_into("<IIII",pe,sec+8,0x1000,0x1000,0x1000,0x400)
    struct.pack_into("<I",pe,sec+36,0x60000020)
    # 0x1f74 - 0x1000 + 0x400 = 0x1374
    for i in range(64):
        pe[0x1374+i]=(i+10)%256
    return pe


class OriginalCallbackRawProofTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.efi=self.folder/"original.efi"
        self.pe=pe_with_executable_section()
        self.persist()
        self.result={
            "address":"0x1f74","requested_bytes":64,
            "returned_bytes":64,"complete":True,
            "bytes_hex":bytes(self.pe[0x1374:0x13b4]).hex(),
        }
        self.record={
            "operation":"read_bytes","provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":impl.PE_SHA256},"architecture":"arm64"},
            "parameters":{"address":"0x1f74","length":64},
            "normalized_result":self.result,"evidence_id":"ev_read_code",
        }
        self.write_read()

    def persist(self):
        self.efi.write_bytes(self.pe)

    def write_read(self):
        (self.folder/impl.CALLBACK_BYTES_EVIDENCE).write_text(
            json.dumps(self.record))

    def proof(self,at="0x1f74"):
        with patch.object(impl,"source_info",return_value={"efiFile":str(self.efi)}):
            with patch.object(impl,"identify_pe",return_value={
                "sha256":impl.PE_SHA256,
                "preferredImageBase":"0x0",
            }):
                return impl.original_code(self.folder,at)

    def both(self):
        with patch.object(impl,"original_code",return_value=self.proof()):
            return impl.imported_code_match(self.folder,"0x1f74")

    def test_original_callback_pointer_maps_to_executable_code(self):
        data=self.proof()
        self.assertEqual(data["coordinate"],"0x1f74")
        self.assertEqual(data["fileOffset"],"0x1374")
        self.assertTrue(data["execSectionVerified"])
        self.assertFalse(data["physicalMemoryInferred"])

    def test_independent_original_and_ghidra_bytes_match(self):
        record=self.both()
        self.assertTrue(record["importedBytesEqualOriginal"])
        self.assertEqual(record["originalGhidraEvidenceId"],"ev_read_code")

    def test_byte_digest_is_finite_and_sha256(self):
        self.assertEqual(len(self.proof()["bytesSha256"]),64)
        self.assertEqual(len(self.proof()["bytesHex"]),128)

    def test_misaligned_arm64_callback_refused(self):
        with self.assertRaisesRegex(ExtractionError,"misaligned"):
            self.proof("0x1f75")

    def test_callback_before_preferred_pe_image_base_refused(self):
        with patch.object(impl,"source_info",return_value={"efiFile":str(self.efi)}):
            with patch.object(impl,"identify_pe",return_value={
                "sha256":impl.PE_SHA256,"preferredImageBase":"0x2000"}):
                with self.assertRaisesRegex(ExtractionError,"negative"):
                    impl.original_code(self.folder,"0x1f74")

    def test_original_executable_flag_required(self):
        sec=0x80+24+0xf0
        struct.pack_into("<I",self.pe,sec+36,0x40000040)
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"not in executable"):
            self.proof()

    def test_original_pe_sha_required(self):
        with patch.object(impl,"source_info",return_value={"efiFile":str(self.efi)}):
            with patch.object(impl,"identify_pe",return_value={
                "sha256":"0"*64,"preferredImageBase":"0x0"}):
                with self.assertRaisesRegex(ExtractionError,"identity mismatch"):
                    impl.original_code(self.folder,"0x1f74")

    def test_unmapped_callback_rva_rejected(self):
        with self.assertRaisesRegex(ExtractionError,"not uniquely backed"):
            self.proof("0x5000")

    def test_truncated_original_callback_section_rejected(self):
        sec=0x80+24+0xf0
        struct.pack_into("<I",self.pe,sec+16,0xf80)
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"not uniquely backed"):
            self.proof()

    def test_overlapping_original_executable_sections_rejected(self):
        sec=0x80+24+0xf0
        struct.pack_into("<H",self.pe,0x80+6,2)
        self.pe[sec+40:sec+80]=self.pe[sec:sec+40]
        self.persist()
        with self.assertRaisesRegex(ExtractionError,"not uniquely backed"):
            self.proof()

    def test_wrong_ghidra_pe_digest_rejected(self):
        self.record["subject"]["digest"]["sha256"]="f"*64
        self.write_read()
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.both()

    def test_wrong_ghidra_read_address_rejected(self):
        self.record["parameters"]["address"]="0x1f70"
        self.write_read()
        with self.assertRaisesRegex(ExtractionError,"target mismatch"):
            self.both()

    def test_incomplete_ghidra_read_rejected(self):
        self.record["normalized_result"]["returned_bytes"]=63
        self.write_read()
        with self.assertRaisesRegex(ExtractionError,"incomplete"):
            self.both()

    def test_different_ghidra_imported_bytes_rejected(self):
        self.record["normalized_result"]["bytes_hex"]="aa"*64
        self.write_read()
        with self.assertRaisesRegex(ExtractionError,"differ"):
            self.both()

    def test_symlink_original_ghidra_evidence_rejected(self):
        f=self.folder/impl.CALLBACK_BYTES_EVIDENCE
        other=self.folder/"saved"
        other.write_bytes(f.read_bytes())
        f.unlink()
        f.symlink_to(other)
        with self.assertRaisesRegex(ExtractionError,"missing"):
            self.both()

    def test_failed_ghidra_callback_partial_is_preserved(self):
        p=self.folder/impl.CALLBACK_PARTIAL
        p.write_text('{"error":"Cannot decompile 0x1f74"}')
        failure=impl.failure_record(self.folder)
        self.assertEqual(failure["status"],"PREVIOUS_GHIDRA_CALLBACK_ANALYSIS_FAILED_OR_PARTIAL")
        self.assertIn("Cannot decompile",failure["files"][0]["excerpt"])
        self.assertFalse(failure["callbackAbsent"])

    def test_unattempted_decompilation_does_not_prove_missing_callback(self):
        result=impl.failure_record(self.folder)
        self.assertEqual(result["status"],"GHIDRA_CALLBACK_FUNCTION_NOT_ANALYZED")
        self.assertFalse(result["callbackAbsent"])

    def test_callback_failure_evidence_symlink_rejected(self):
        p=self.folder/impl.CALLBACK_PARTIAL
        other=self.folder/"actual-error"
        other.write_text("error")
        p.symlink_to(other)
        with self.assertRaisesRegex(ExtractionError,"Symlinked"):
            impl.failure_record(self.folder)

    def test_oversized_failed_ghidra_output_rejected(self):
        p=self.folder/impl.CALLBACK_STDERR
        p.write_bytes(b"x"*(impl.MAX_FAILURE_LOG+1))
        with self.assertRaisesRegex(ExtractionError,"oversized"):
            impl.failure_record(self.folder)


if __name__=="__main__":
    unittest.main()
