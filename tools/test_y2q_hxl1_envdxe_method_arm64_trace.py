#!/usr/bin/env python3
"""195 distinct original-XBL four-method/direct-callee provenance regressions.

Matrix independently exercises every real interface slot (08/10/18/20)
against Ghidra request/result identity, executable source bytes, malformed
evidence and provenance. These are not duplicate assertions against one slot.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_method_arm64_trace as mod
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def image():
    pe=bytearray([i%256 for i in range(0x6000)])
    pe[:2]=b"MZ"
    struct.pack_into("<I",pe,0x3c,0x80)
    pe[0x80:0x84]=b"PE\0\0"
    struct.pack_into("<H",pe,0x80+6,1)
    struct.pack_into("<H",pe,0x80+20,0xf0)
    sec=0x80+24+0xf0
    pe[sec:sec+8]=b".text\0\0\0"
    struct.pack_into("<IIII",pe,sec+8,0x5000,0x1000,0x5000,0x400)
    struct.pack_into("<I",pe,sec+36,0x60000020)
    offset=0x400+(0x1f74-0x1000)+0x30
    struct.pack_into("<I",pe,offset,0x94000cca)
    return pe


def base_parent():
    return {
        "exactOriginalEnvDxeSha256":mod.PE_SHA256,
        "runtimeRegistrationSuccessful":False,
        "runtimeRamPartitionTableMeasured":False,
        "kernelPhysicalLoadMeasured":False,
        "protocolInterfaceStructure":{
            "shaPinnedOriginalGhidraEvidenceId":"ev_interface",
            "qwordsHex":["0x10001","0x1ee8","0x1f0c","0x1f74","0x1f28","0x10001"],
            "getRamPartitionsSlotStaticAddress":"0xd1e8",
            "getRamPartitionsSlotRawQword":"0x1f74",
        },
        "originalCallbackGhidraReadback":{
            "importedBytesEqualOriginal":True,
            "bytesSha256":mod.CALLBACK_FIRST64_SHA,
        },
    }


def record(label,at,blob):
    return {
        "operation":"read_bytes",
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":mod.PE_SHA256},"architecture":"arm64"},
        "parameters":{"address":at,"length":mod.WINDOW},
        "evidence_id":"ev_window_"+label,
        "normalized_result":{
            "address":at,"requested_bytes":mod.WINDOW,
            "returned_bytes":mod.WINDOW,"complete":True,
            "bytes_hex":blob.hex(),
        },
    }


class FourMethodProvenanceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder=Path(tmp.name)
        self.pe=image()
        self.file=self.folder/"original.efi"
        self.file.write_bytes(self.pe)
        self.parent=base_parent()
        self.doc={}
        for label,_,at in list(mod.EXPECTED_SLOTS)+[
                (name,-1,addr) for name,addr in mod.ADDITIONAL_CODE_LEADS]:
            off=0x400+(int(at,16)-0x1000)
            self.doc[label]=record(label,at,self.pe[off:off+mod.WINDOW])
        self.write_all()

    def write_all(self):
        for label,doc in self.doc.items():
            self.path(label).write_text(json.dumps(doc))

    def path(self,label):
        return self.folder/("rea-envdxe-method-window-"+label+".json")

    def window(self,at,size=mod.WINDOW):
        with patch.object(mod,"source_info",return_value={"efiFile":str(self.file)}):
            with patch.object(mod,"identify_pe",return_value={
                "sha256":mod.PE_SHA256,"preferredImageBase":"0x0",
            }):
                return mod.original_window(self.folder,at,size)

    def imported(self,label):
        at=next(at for name,_,at in list(mod.EXPECTED_SLOTS)+[
            (name,-1,addr) for name,addr in mod.ADDITIONAL_CODE_LEADS
        ] if name==label)
        src=self.window(at)
        return mod.imported_window(self.folder,label,at,src)

    def full(self):
        with patch.object(mod,"parent_audit",return_value=self.parent):
            with patch.object(mod,"source_info",return_value={"efiFile":str(self.file)}):
                with patch.object(mod,"identify_pe",return_value={
                    "sha256":mod.PE_SHA256,"preferredImageBase":"0x0"
                }):
                    return mod.report(self.folder)

    def test_all_four_method_windows_and_callback_branch_verified(self):
        result=self.full()
        self.assertEqual(len(result["methods"]),4)
        self.assertEqual(result["verifiedGetRamPartitionsDirectCallee"],"0x52cc")
        self.assertTrue(all(x["ghidraCode"]["originalBytesMatchImported"]
                            for x in result["methods"]))
        self.assertFalse(result["livePhysicalMemoryObserved"])
        self.assertFalse(result["privilegeEscalationDemonstrated"])

    def test_exact_callback_bl_address_and_target(self):
        at="0x1f74";code=self.window(at)
        calls=[x for x in code["edges"] if x["mnemonicClass"]=="BL"]
        self.assertIn({"instructionAddress":"0x1fa4",
                       "rawWord":"0x94000cca","mnemonicClass":"BL",
                       "directBranchTarget":"0x52cc",
                       "runtimeExecutionObserved":False},calls)

    def test_synthetic_section_includes_all_five_observed_code_windows(self):
        """Regression: the fifth, 0x52cc, was beyond the former 0x5000 RVA limit."""
        sec=0x80+24+0xf0
        virtual_size,rva,raw_size,file_offset=struct.unpack_from(
            "<IIII",self.pe,sec+8)
        self.assertEqual(rva,0x1000)
        self.assertEqual(raw_size,0x5000)
        self.assertEqual(virtual_size,0x5000)
        self.assertGreaterEqual(len(self.pe),file_offset+raw_size)
        for label,_,at in list(mod.EXPECTED_SLOTS)+[
                (name,-1,addr) for name,addr in mod.ADDITIONAL_CODE_LEADS]:
            with self.subTest(label=label,at=at):
                value=int(at,16)
                self.assertGreaterEqual(value,rva)
                self.assertLessEqual(value+mod.WINDOW,rva+raw_size)
                mapped=self.window(at)
                self.assertEqual(mapped["staticAddress"],at)
                self.assertEqual(len(bytes.fromhex(mapped["bytesHex"])),mod.WINDOW)

    def test_callee_rejected_if_executable_section_ends_before_0x52cc(self):
        """Ensure real analyzer mapping stays fail-closed if the section is short."""
        sec=0x80+24+0xf0
        struct.pack_into("<IIII",self.pe,sec+8,0x4000,0x1000,0x4000,0x400)
        self.file.write_bytes(self.pe)
        with self.assertRaisesRegex(ExtractionError,"does not uniquely map"):
            self.window("0x52cc")
        # All four method pointers remain inside the smaller original fixture.
        for _,_,at in mod.EXPECTED_SLOTS:
            self.assertEqual(self.window(at)["staticAddress"],at)

    def test_fifth_direct_callee_window_is_proven_in_same_pass(self):
        result=self.full()
        self.assertEqual(len(result["methods"]),4)
        self.assertEqual(len(result["directCalleeCode"]),1)
        self.assertEqual(result["directCalleeCode"][0]["code"]["staticAddress"],"0x52cc")
        self.assertTrue(result["directCalleeCode"][0]["ghidraCode"]
                        ["originalBytesMatchImported"])
        self.assertFalse(result["directCalleeCode"][0]["functionExtentInferred"])

    def test_callback_synthetic_bl_0x52cc_is_not_live_execution(self):
        outcome=self.full()
        self.assertFalse(outcome["callbackRuntimeInvocationObserved"])
        self.assertFalse(outcome["kernelSuInstalled"])

    def test_unverified_runtime_parent_is_refused(self):
        self.parent["kernelPhysicalLoadMeasured"]=True
        with self.assertRaisesRegex(ExtractionError,"improperly promotes"):
            self.full()

    def test_original_iface_qword_change_refused(self):
        self.parent["protocolInterfaceStructure"]["qwordsHex"][3]="0x1f78"
        with self.assertRaisesRegex(ExtractionError,"layout changed"):
            self.full()

    def test_get_ram_callback_readback_must_agree_with_original(self):
        self.parent["originalCallbackGhidraReadback"]["bytesSha256"]="0"*64
        with self.assertRaisesRegex(ExtractionError,"not independently corroborated"):
            self.full()

    def test_report_without_imported_method_evidence_can_preserve_partial(self):
        self.path("method-08").unlink()
        result=self.full()
        self.assertIsNone(result["methods"][0]["ghidraCode"])
        self.assertEqual(result["methods"][0]["originalCode"]["staticAddress"],"0x1ee8")

    def test_report_rejects_missing_import_when_strict(self):
        self.path("method-08").unlink()
        with patch.object(mod,"parent_audit",return_value=self.parent):
            with patch.object(mod,"source_info",return_value={"efiFile":str(self.file)}):
                with patch.object(mod,"identify_pe",return_value={
                    "sha256":mod.PE_SHA256,"preferredImageBase":"0x0"}):
                    with self.assertRaisesRegex(ExtractionError,"Missing original Ghidra"):
                        mod.report(self.folder,allow_missing=False)

    def test_direct_bl_negative_displacement_decodes_correctly(self):
        code=struct.pack("<I",0x97ffffff)
        edge=mod.arm64_edges(code,0x4000)[0]
        self.assertEqual(edge["mnemonicClass"],"BL")
        self.assertEqual(edge["directBranchTarget"],"0x3ffc")

    def test_direct_bl_max_positive_displacement_decodes_correctly(self):
        code=struct.pack("<I",0x95ffffff)
        edge=mod.arm64_edges(code,0x4000)[0]
        self.assertEqual(edge["directBranchTarget"],hex(0x4000+(0x1ffffff*4)))

    def test_conditional_branch_forward(self):
        # B.cond +8: imm19=2
        edge=mod.arm64_edges(struct.pack("<I",0x54000040),0x1000)[0]
        self.assertEqual(edge["directBranchTarget"],"0x1008")

    def test_return_is_not_labeled_direct_call(self):
        edge=mod.arm64_edges(struct.pack("<I",0xd65f03c0),0x8000)[0]
        self.assertEqual(edge["mnemonicClass"],"RET")
        self.assertIsNone(edge["directBranchTarget"])

    def test_blr_is_indirect_and_no_static_target(self):
        edge=mod.arm64_edges(struct.pack("<I",0xd63f0000),0x8000)[0]
        self.assertEqual(edge["mnemonicClass"],"BLR")
        self.assertIsNone(edge["directBranchTarget"])

    def test_invalid_arm64_window_length_refused(self):
        with self.assertRaisesRegex(ExtractionError,"Unaligned"):
            mod.arm64_edges(b"\x00"*3,0x1000)

    def test_original_code_mapping_requires_unique_section(self):
        struct.pack_into("<H",self.pe,0x80+6,0)
        self.file.write_bytes(self.pe)
        with self.assertRaisesRegex(ExtractionError,"uniquely map"):
            self.window("0x1f74")

    def test_original_code_requires_executable_section(self):
        sec=0x80+24+0xf0
        struct.pack_into("<I",self.pe,sec+36,0x40000040)
        self.file.write_bytes(self.pe)
        with self.assertRaisesRegex(ExtractionError,"not within PE executable"):
            self.window("0x1f74")

    def test_synthetic_pe_altered_identity_refused(self):
        with patch.object(mod,"source_info",return_value={"efiFile":str(self.file)}):
            with patch.object(mod,"identify_pe",return_value={
                "sha256":"0"*64,"preferredImageBase":"0x0"}):
                with self.assertRaisesRegex(ExtractionError,"identity changed"):
                    mod.original_window(self.folder,"0x1f74")

    def test_unaligned_window_coordinate_refused(self):
        with self.assertRaisesRegex(ExtractionError,"Invalid ARM64"):
            self.window("0x1f75")

    def test_oversized_window_refused(self):
        with self.assertRaisesRegex(ExtractionError,"Invalid ARM64"):
            self.window("0x1f74",8192)

    def test_cross_method_128_byte_windows_are_not_complete_functions(self):
        result=self.full()
        self.assertTrue(all(
            item["originalCode"]["windowIsCompleteFunction"] is False
            for item in result["methods"]))


def operation(v):
    return lambda rec:rec.__setitem__("operation",v)
def provider(v):
    return lambda rec:rec["provider"].__setitem__("id",v)
def sha(v):
    return lambda rec:rec["subject"]["digest"].__setitem__("sha256",v)
def arch(v):
    return lambda rec:rec["subject"].__setitem__("architecture",v)
def evidence(v):
    return lambda rec:rec.__setitem__("evidence_id",v)
def param(k,v):
    return lambda rec:rec["parameters"].__setitem__(k,v)
def result(k,v):
    return lambda rec:rec["normalized_result"].__setitem__(k,v)

# 35 distinct negative REA provenance mutations for each of five real
# targets (four original EFI method slots and the direct 0x52cc callee).
CASE_MUTATIONS=(
 ("wrong_operation_xrefs", operation("xrefs"),"query mismatch"),
 ("wrong_operation_function", operation("analyze_function"),"query mismatch"),
 ("wrong_operation_null", operation(None),"query mismatch"),
 ("provider_rizin",provider("rizin"),"not bound"),
 ("provider_null",provider(None),"not bound"),
 ("provider_empty",provider(""),"not bound"),
 ("wrong_sha",sha("0"*64),"not bound"),
 ("missing_sha",sha(None),"not bound"),
 ("wrong_arch_x86",arch("x86_64"),"not bound"),
 ("wrong_arch_arm32",arch("arm"),"not bound"),
 ("wrong_arch_null",arch(None),"not bound"),
 ("evidence_id_null",evidence(None),"not bound"),
 ("evidence_id_empty",evidence(""),"not bound"),
 ("wrong_address",param("address","0x1000"),"query mismatch"),
 ("missing_address",param("address",None),"query mismatch"),
 ("empty_address",param("address",""),"query mismatch"),
 ("read_64_instead_128",param("length",64),"query mismatch"),
 ("read_256_instead_128",param("length",256),"query mismatch"),
 ("length_string",param("length","128"),"query mismatch"),
 ("length_none",param("length",None),"query mismatch"),
 ("return_address_wrong",result("address","0x1000"),"incomplete"),
 ("return_address_none",result("address",None),"incomplete"),
 ("requested_short",result("requested_bytes",127),"incomplete"),
 ("requested_zero",result("requested_bytes",0),"incomplete"),
 ("returned_short",result("returned_bytes",127),"incomplete"),
 ("returned_long",result("returned_bytes",129),"incomplete"),
 ("complete_false",result("complete",False),"incomplete"),
 ("complete_null",result("complete",None),"incomplete"),
 ("bytes_hex_empty",result("bytes_hex",""),"incomplete"),
 ("bytes_hex_bad_char",result("bytes_hex","zz"*128),"incomplete"),
 ("bytes_hex_short",result("bytes_hex","aa"*127),"incomplete"),
 ("bytes_hex_long",result("bytes_hex","aa"*129),"incomplete"),
 ("bytes_hex_wrong",result("bytes_hex","aa"*128),"differ"),
 ("result_none",lambda rec:rec.__setitem__("normalized_result",None),"incomplete"),
 ("result_wrong_shape",lambda rec:rec.__setitem__("normalized_result",[]),"incomplete"),
)


for label in [x[0] for x in mod.EXPECTED_SLOTS]+[
        x[0] for x in mod.ADDITIONAL_CODE_LEADS]:
    for suffix,mutate,expected in CASE_MUTATIONS:
        def factory(current_label,mutation,match):
            def t(self):
                self.doc[current_label]=copy.deepcopy(self.doc[current_label])
                mutation(self.doc[current_label])
                self.path(current_label).write_text(json.dumps(self.doc[current_label]))
                with self.assertRaisesRegex(ExtractionError,match):
                    self.imported(current_label)
            return t
        setattr(FourMethodProvenanceTests,"test_"+label.replace("-","_")+"_"+suffix,
                factory(label,mutate,expected))


if __name__=="__main__":
    unittest.main()
