#!/usr/bin/env python3
"""Eight original ARM64 callback leads: independent binary and provenance gates.

Each mutation is run against EVERY distinct code target, not just one fake
source. No on-device execution, runtime table claim, or firmware modification.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_envdxe_helper_batch as stage
from tools import y2q_hxl1_envdxe_method_arm64_trace as prev
from tools.y2q_hxl1_extract_envdxe import ExtractionError


SEC=0x80+24+0xf0

def fake_pe():
    pe=bytearray([i%256 for i in range(0xa000)])
    pe[:2]=b"MZ"
    struct.pack_into("<I",pe,0x3c,0x80)
    pe[0x80:0x84]=b"PE\0\0"
    struct.pack_into("<H",pe,0x80+6,1)
    struct.pack_into("<H",pe,0x80+20,0xf0)
    pe[SEC:SEC+8]=b".text\0\0\0"
    struct.pack_into("<IIII",pe,SEC+8,0x9000,0x1000,0x9000,0x400)
    struct.pack_into("<I",pe,SEC+36,0x60000020)
    def write(address,word):
        struct.pack_into("<I",pe,0x400+(address-0x1000),word)
    write(0x52f4,0xb4000533)  # CBZ => 0x5398
    write(0x532c,0x14000017)  # B => 0x5388
    write(0x5340,0x97fffa3f)  # BL => 0x3c3c
    return pe


def parent_fixture(pe):
    off=0x400+(0x52cc-0x1000)
    first=pe[off:off+128]
    helper_edges=prev.arm64_edges(first,0x52cc)
    methods=[]
    for label,start,end in (
        ("method-08","0x1ee8","0x1f0c"),
        ("method-10","0x1f0c","0x1f28"),
        ("method-20","0x1f28","0x1f74"),
        ("get-ram-partitions","0x1f74","0x1fe8"),
    ):
        own=[]
        if label=="method-20":
            own=[{"mnemonicClass":"BL","instructionAddress":"0x1f40",
                  "directBranchTarget":"0x5740"}]
        if label=="get-ram-partitions":
            own=[{"mnemonicClass":"BL","instructionAddress":"0x1fa4",
                  "directBranchTarget":"0x52cc"}]
        methods.append({
            "role":label,
            "originalCode":{"staticAddress":start},
            "ghidraCode":{"originalBytesMatchImported":True},
            "boundedInterpretation":{
                "exclusiveUpperBound":end,
                "boundaryIsVerifiedGhidraFunctionEnd":False,
                "inRegionControlFlow":own,
            },
        })
    return {
        "sha256PinnedEnvDxe":stage.PE_SHA256,
        "livePhysicalMemoryObserved":False,
        "privilegeEscalationDemonstrated":False,
        "kernelSuInstalled":False,
        "originalInterfaceEvidenceId":"ev_interface",
        "methods":methods,
        "directCalleeCode":[{
            "code":{"staticAddress":"0x52cc",
                    "bytesHex":first.hex(),"edges":helper_edges},
            "ghidraCode":{"originalBytesMatchImported":True},
        }],
    }


def imported_record(label,addr,size,blob):
    return {
        "operation":"read_bytes",
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":stage.PE_SHA256},"architecture":"arm64"},
        "parameters":{"address":addr,"length":size},
        "evidence_id":"ev_"+label,
        "normalized_result":{
            "address":addr,"requested_bytes":size,
            "returned_bytes":size,"complete":True,
            "bytes_hex":blob.hex(),
        },
    }


class HelperEightCodeWindowTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder=Path(tmp.name)
        self.pe=fake_pe()
        self.file=self.folder/"original.efi"
        self.file.write_bytes(self.pe)
        self.parent=parent_fixture(self.pe)
        self.records={}
        for label,at,size in stage.WINDOWS:
            off=0x400+(int(at,16)-0x1000)
            self.records[label]=imported_record(
                label,at,size,self.pe[off:off+size])
            self.write_window(label)
        for label,at in stage.XREFS:
            (self.folder/("rea-envdxe-helper-xrefs-"+label+".json")).write_text(
                json.dumps({
                    "operation":"xrefs","provider":{"id":"ghidra"},
                    "subject":{"digest":{"sha256":stage.PE_SHA256},"architecture":"arm64"},
                    "parameters":{"address":at},
                    "evidence_id":"ev_ref_"+label,
                    "normalized_result":["0x1230","0x1234"],
                }))

    def window_path(self,label):
        return self.folder/("rea-envdxe-helper-window-"+label+".json")

    def write_window(self,label):
        self.window_path(label).write_text(json.dumps(self.records[label]))

    def source(self,addr,size):
        with patch.object(prev,"source_info",return_value={"efiFile":str(self.file)}):
            with patch.object(prev,"identify_pe",return_value={
                "sha256":stage.PE_SHA256,"preferredImageBase":"0x0",
            }):
                return stage.original_window(self.folder,addr,size)

    def verify(self,label):
        name,at,size=next(x for x in stage.WINDOWS if x[0]==label)
        raw=self.source(at,size)
        return stage.imported_code(self.folder,name,at,size,raw)

    def aggregate(self,strict=True):
        with patch.object(stage,"method_audit",return_value=self.parent):
            with patch.object(prev,"source_info",return_value={"efiFile":str(self.file)}):
                with patch.object(prev,"identify_pe",return_value={
                    "sha256":stage.PE_SHA256,"preferredImageBase":"0x0",
                }):
                    return stage.report(self.folder,strict=strict)

    def test_all_eight_original_code_targets_in_single_report(self):
        doc=self.aggregate()
        self.assertEqual(len(doc["eightCodeWindows"]),8)
        self.assertEqual(len(doc["targetedXrefs"]),4)
        self.assertTrue(all(x["ghidraImported"]["originalBytesMatch"]
                            for x in doc["eightCodeWindows"]))
        self.assertFalse(doc["bootTimeRamTableValuesMeasured"])
        self.assertFalse(doc["kernelPhysicalEntryObserved"])

    def test_224_byte_helper_contains_original_128_byte_evidence(self):
        outcome=self.aggregate()["eightCodeWindows"][0]
        self.assertEqual(outcome["size"],224)
        self.assertTrue(outcome["originalPe"]["bytesHex"].startswith(
            self.parent["directCalleeCode"][0]["code"]["bytesHex"]))

    def test_direct_0x5340_branch_proven_0x3c3c(self):
        report=self.aggregate()
        helper=report["eightCodeWindows"][0]
        self.assertIn("0x3c3c",[
            x["directBranchTarget"] for x in helper["originalPe"]["edges"]
            if x["instructionAddress"]=="0x5340" and x["mnemonicClass"]=="BL"])

    def test_original_getram_does_not_own_post_return_bl(self):
        self.assertTrue(self.aggregate()["methodOwnershipCorrected"])
        self.parent["methods"][3]["boundedInterpretation"][
            "inRegionControlFlow"].append({
                "mnemonicClass":"BL","instructionAddress":"0x1ff0",
                "directBranchTarget":"0x2618"})
        with self.assertRaisesRegex(ExtractionError,"Post-return"):
            self.aggregate()

    def test_helper_parent_branch_identity_cannot_be_changed(self):
        self.parent["directCalleeCode"][0]["code"]["edges"][0][
            "directBranchTarget"]="0xbad"
        # Regardless of the ordering of the first edge, the required map
        # must retain the exact validated original branch destinations.
        if self.parent["directCalleeCode"][0]["code"]["edges"][0]["instructionAddress"] not in (
                "0x52f4","0x532c","0x5340"):
            self.parent["directCalleeCode"][0]["code"]["edges"]=[
                {"instructionAddress":"0x5340","directBranchTarget":"0xbeef"}]
        with self.assertRaisesRegex(ExtractionError,"branching/control flow"):
            self.aggregate()

    def test_error_flag_cannot_be_promoted_to_kernel_root(self):
        self.parent["kernelSuInstalled"]=True
        with self.assertRaisesRegex(ExtractionError,"incorrectly promoted"):
            self.aggregate()

    def test_invalid_other_method_source_cannot_be_promoted(self):
        self.parent["methods"][2]["boundedInterpretation"][
            "inRegionControlFlow"][0]["directBranchTarget"]="0x3c3c"
        with self.assertRaisesRegex(ExtractionError,"other method"):
            self.aggregate()

    def test_pe_section_genuinely_unbacked_is_rejected(self):
        struct.pack_into("<IIII",self.pe,SEC+8,0x4000,0x1000,0x4000,0x400)
        self.file.write_bytes(self.pe)
        with self.assertRaisesRegex(ExtractionError,"uniquely map"):
            self.source("0x81f4",128)

    def test_missing_saved_ghidra_window_can_be_marked_not_measured(self):
        self.window_path("additional-smem-caller").unlink()
        partial=self.aggregate(strict=False)
        self.assertIsNone(partial["eightCodeWindows"][-1]["ghidraImported"])
        with self.assertRaisesRegex(ExtractionError,"Missing Ghidra"):
            self.aggregate(strict=True)

    def test_four_reference_targets_are_not_runtime_callers(self):
        output=self.aggregate()
        self.assertTrue(all(r["runtimeReachabilityConfirmed"] is False
                            for r in output["targetedXrefs"]))

    def test_ghidra_reference_coordinate_refused_if_wrong(self):
        p=self.folder/"rea-envdxe-helper-xrefs-ram-helper-copy-callee.json"
        obj=json.loads(p.read_text())
        obj["parameters"]["address"]="0x1f74"
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ExtractionError,"xref query"):
            self.aggregate()

    def test_ghidra_reference_input_shape_must_be_bounded(self):
        p=self.folder/"rea-envdxe-helper-xrefs-ram-helper-copy-callee.json"
        obj=json.loads(p.read_text())
        obj["normalized_result"]=["0x1234"]*(stage.MAX_REFS+1)
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ExtractionError,"Unbounded"):
            self.aggregate()

    def test_helper_windows_are_not_full_function_dossiers(self):
        result=self.aggregate()
        self.assertFalse(any(x["inferredFullFunction"]
                             for x in result["eightCodeWindows"]))

    def test_explicit_static_address_cannot_be_confused_with_kernel_base(self):
        report=self.aggregate()
        self.assertFalse(report["kernelPhysicalEntryObserved"])
        self.assertIn("never runtime",stage.render(report))


def change_operation(value):
    return lambda rec:rec.__setitem__("operation",value)
def change_provider(value):
    return lambda rec:rec["provider"].__setitem__("id",value)
def change_digest(value):
    return lambda rec:rec["subject"]["digest"].__setitem__("sha256",value)
def change_arch(value):
    return lambda rec:rec["subject"].__setitem__("architecture",value)
def change_evid(value):
    return lambda rec:rec.__setitem__("evidence_id",value)
def change_param(field,value):
    return lambda rec:rec["parameters"].__setitem__(field,value)
def change_result(field,value):
    return lambda rec:rec["normalized_result"].__setitem__(field,value)

MUTATIONS=(
 ("operation_xrefs",change_operation("xrefs"),"operation/coordinates"),
 ("operation_function",change_operation("analyze_function"),"operation/coordinates"),
 ("operation_null",change_operation(None),"operation/coordinates"),
 ("provider_rizin",change_provider("rizin"),"not bound"),
 ("provider_empty",change_provider(""),"not bound"),
 ("provider_none",change_provider(None),"not bound"),
 ("foreign_sha",change_digest("f"*64),"not bound"),
 ("missing_sha",change_digest(None),"not bound"),
 ("foreign_arm32",change_arch("arm"),"not bound"),
 ("foreign_x64",change_arch("x86_64"),"not bound"),
 ("missing_arch",change_arch(None),"not bound"),
 ("empty_evidence_id",change_evid(""),"not bound"),
 ("null_evidence_id",change_evid(None),"not bound"),
 ("address_wrong",change_param("address","0x1f74"),"operation/coordinates"),
 ("address_none",change_param("address",None),"operation/coordinates"),
 ("address_empty",change_param("address",""),"operation/coordinates"),
 ("length_wrong_16",change_param("length",16),"operation/coordinates"),
 ("length_wrong_256",change_param("length",256),"operation/coordinates"),
 ("length_string",change_param("length","128"),"operation/coordinates"),
 ("length_null",change_param("length",None),"operation/coordinates"),
 ("returned_address_wrong",change_result("address","0x1000"),"Incomplete"),
 ("returned_address_none",change_result("address",None),"Incomplete"),
 ("requested_size_short",change_result("requested_bytes",0),"Incomplete"),
 ("requested_size_long",change_result("requested_bytes",10000),"Incomplete"),
 ("returned_size_short",change_result("returned_bytes",0),"Incomplete"),
 ("returned_size_long",change_result("returned_bytes",10000),"Incomplete"),
 ("complete_false",change_result("complete",False),"Incomplete"),
 ("complete_none",change_result("complete",None),"Incomplete"),
 ("hex_empty",change_result("bytes_hex",""),"Incomplete"),
 ("hex_null",change_result("bytes_hex",None),"Incomplete"),
 ("hex_bad",change_result("bytes_hex","zz"*128),"Incomplete"),
 ("hex_wrong",change_result("bytes_hex","aa"*256),"Incomplete|differ"),
 ("normalized_null",lambda r:r.__setitem__("normalized_result",None),"Incomplete"),
 ("normalized_list",lambda r:r.__setitem__("normalized_result",[]),"Incomplete"),
 ("normalized_empty_dict",lambda r:r.__setitem__("normalized_result",{}),"Incomplete"),
 ("raw_wrong_operation",change_operation("search_strings"),"operation/coordinates"),
 ("provider_unknown",change_provider("other"),"not bound"),
 ("missing_architecture",change_arch(""),"not bound"),
 ("digest_all_zero",change_digest("0"*64),"not bound"),
 ("requested_boolean",change_result("requested_bytes",True),"Incomplete"),
)


for label,_,_ in stage.WINDOWS:
    for suffix,mutation,error in MUTATIONS:
        def make_test(role,mutate,expected):
            def test(self):
                self.records[role]=copy.deepcopy(self.records[role])
                mutate(self.records[role])
                self.write_window(role)
                with self.assertRaisesRegex(ExtractionError,expected):
                    self.verify(role)
            return test
        setattr(HelperEightCodeWindowTests,
                "test_"+label.replace("-","_")+"_"+suffix,
                make_test(label,mutation,error))


if __name__=="__main__":
    unittest.main()
