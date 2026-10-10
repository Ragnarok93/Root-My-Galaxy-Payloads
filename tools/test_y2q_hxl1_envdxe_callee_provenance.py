#!/usr/bin/env python3
"""Ghidra/PE provenance, previous-callback call graph and 3-callee mutations.

Every change to the first 64 bytes of each distinct callee's saved imported
code is individually tested (3 x 64 x 8 = 1536 separate regressions).
These tests exercise real source/import comparison and JSON provenance,
not a claim of physical execution.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_callee_provenance as audit
from tools.y2q_hxl1_extract_envdxe import ExtractionError


def prior_callback():
    return {
        "originalEnvDxeSha256":audit.PE_SHA256,
        "runtimePhysicalRamKnown":False,
        "kernelPhysicalLoadKnown":False,
        "exploitOrRootAchieved":False,
        "threeOriginalGhidraReadbacks":{"originalSha256":"source_sha"},
        "cfg":{
            "outOfWindowSuccessors":[],
            "reachableCalls":[
                {"pc":"0x1fa4","target":"0x52cc"},
                {"pc":"0x1ff0","target":"0x2618"},
                {"pc":"0x2004","target":"0x52cc"},
                {"pc":"0x2050","target":"0x26bc"},
            ],
        },
    }


def old_helper():
    def source(label,ops):
        return {
            "label":label,
            "ghidraImported":{"originalBytesMatch":True},
            "originalPe":{"edges":[
                {"instructionAddress":at,"mnemonicClass":"BL",
                 "directBranchTarget":target}
                for at,target in ops
            ]},
        }
    return {
        "originalEnvDxeSha256":audit.PE_SHA256,
        "rootPrivilegeDemonstrated":False,
        "eightCodeWindows":[
            source("post-callback-callee",[("0x2638","0x25d8")]),
            source("ram-helper-copy-callee",[
                ("0x3c60","0x3d04"),("0x3c74","0x3d04"),
            ]),
        ],
    }


def evidence(operation,addr,size,code=None,expected=None):
    return {
        "operation":operation,
        "provider":{"id":"ghidra"},
        "subject":{"digest":{"sha256":audit.PE_SHA256},
                   "architecture":"arm64"},
        "evidence_id":"ev_local_test_"+addr,
        "parameters":{"address":addr,**(
            {"length":size} if operation=="read_bytes" else {}
        )},
        "normalized_result":(
            {"address":addr,"requested_bytes":size,
             "returned_bytes":size,"complete":True,
             "bytes_hex":code.hex()} if operation=="read_bytes"
            else list(expected)
        ),
    }


class CalleeEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder=Path(temp.name)
        self.cb=prior_callback()
        self.old=old_helper()
        self.original={}
        self.saved={}
        for index,(label,at,size,req) in enumerate(audit.WINDOWS):
            data=bytes(((index*19+j*5)&255) for j in range(size))
            self.original[label]={
                "staticAddress":at,"size":size,"sectionName":".text",
                "peFileOffset":at,"bytesHex":data.hex(),
                "sha256":hashlib.sha256(data).hexdigest(),
                "edges":[],
            }
            self.saved[label]=evidence("read_bytes",at,size,data)
            self.write_bytes(label)
            self.write_refs(label)

    def path_bytes(self,label):
        return self.folder/f"{audit.NAME}-bytes-{label}.json"

    def write_bytes(self,label):
        self.path_bytes(label).write_text(json.dumps(self.saved[label]))

    def path_refs(self,label):
        return self.folder/f"{audit.NAME}-refs-{label}.json"

    def write_refs(self,label):
        at,req=next((at,req) for lab,at,_,req in audit.WINDOWS if lab==label)
        self.path_refs(label).write_text(json.dumps(
            evidence("xrefs",at,None,expected=req)
        ))

    def verify(self,label):
        l,at,size,_=next(x for x in audit.WINDOWS if x[0]==label)
        return audit.imported(self.folder,l,at,size,self.original[l])

    def full(self,strict=True):
        def window(folder,at,size):
            return next(self.original[label] for label,a,n,_ in audit.WINDOWS
                        if a==at and n==size)
        with patch.object(audit,"callback_audit",return_value=self.cb):
            with patch.object(audit,"helper_audit",return_value=self.old):
                with patch.object(audit,"original_window",side_effect=window):
                    return audit.report(self.folder,strict=strict)

    def test_three_original_callees_and_all_references_verified(self):
        value=self.full()
        self.assertEqual(len(value["additionalOriginalTargetReadbacks"]),3)
        self.assertTrue(all(x["importedOriginalGhidraCode"]["match"]
                            for x in value["additionalOriginalTargetReadbacks"]))
        self.assertTrue(all(x["staticXrefs"] is not None
                            for x in value["additionalOriginalTargetReadbacks"]))
        self.assertFalse(value["liveRamPartitionsMeasured"])
        self.assertFalse(value["kernelPhysicalBaseKnown"])
        self.assertFalse(value["rootOrKernelSuDemonstrated"])

    def test_static_callee_classification_not_assumed(self):
        value=self.full()
        self.assertTrue(all(x["boundaryGhidraVerified"] is False and
                            x["semanticsInferredFromName"] is False
                            for x in value["additionalOriginalTargetReadbacks"]))

    def test_all_reference_counts_correspond_to_unique_static_callsites(self):
        value=self.full()
        refs=[x["staticXrefs"] for x in value["additionalOriginalTargetReadbacks"]]
        self.assertEqual([x["sourceCount"] for x in refs],[1,1,2])
        self.assertTrue(all(x["dynamicExecutionVerified"] is False for x in refs))

    def test_parent_rejects_unconfirmed_new_0x26bc_call(self):
        self.cb["cfg"]["reachableCalls"][-1]["target"]="0xdead"
        with self.assertRaisesRegex(ExtractionError,"four-reachable-call"):
            self.full()

    def test_parent_rejects_physical_kernel_address_claim(self):
        self.cb["kernelPhysicalLoadKnown"]=True
        with self.assertRaisesRegex(ExtractionError,"proof boundary"):
            self.full()

    def test_parent_rejects_wrong_3d04_caller(self):
        target=self.old["eightCodeWindows"][1]["originalPe"]["edges"]
        target[1]["directBranchTarget"]="0xbeef"
        with self.assertRaisesRegex(ExtractionError,"caller direct branches"):
            self.full()

    def test_parent_rejects_wrong_2618_secondary_helper(self):
        target=self.old["eightCodeWindows"][0]["originalPe"]["edges"]
        target[0]["directBranchTarget"]="0xbeef"
        with self.assertRaisesRegex(ExtractionError,"caller direct branches"):
            self.full()

    def test_parent_rejects_missing_authentic_ghidra_caller(self):
        self.old["eightCodeWindows"][0]["ghidraImported"]={"originalBytesMatch":False}
        with self.assertRaisesRegex(ExtractionError,"not authenticated"):
            self.full()

    def test_genuine_missing_code_record_is_explicitly_missing(self):
        self.path_bytes("callback-tail-callee").unlink()
        result=self.full(strict=False)
        self.assertIsNone(result["additionalOriginalTargetReadbacks"][0]["importedOriginalGhidraCode"])
        with self.assertRaisesRegex(ExtractionError,"Missing original Ghidra"):
            self.full(strict=True)

    def test_genuine_missing_xref_record_is_explicitly_missing(self):
        self.path_refs("secondary-ram-helper").unlink()
        result=self.full(strict=False)
        self.assertIsNone(result["additionalOriginalTargetReadbacks"][1]["staticXrefs"])
        with self.assertRaisesRegex(ExtractionError,"Missing original Ghidra"):
            self.full(strict=True)

    def test_required_ref_cannot_be_hidden(self):
        p=self.path_refs("record-copy-subroutine")
        obj=json.loads(p.read_text())
        obj["normalized_result"]=["0x3c60"]
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ExtractionError,"known static callers absent"):
            self.full()

    def test_reference_coordinate_cannot_be_forged(self):
        p=self.path_refs("callback-tail-callee")
        obj=json.loads(p.read_text())
        obj["parameters"]["address"]="0x1234"
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ExtractionError,"request identity"):
            self.full()

    def test_non_ghidra_provenance_rejected(self):
        obj=self.saved["callback-tail-callee"]
        obj["provider"]["id"]="rizin"
        self.write_bytes("callback-tail-callee")
        with self.assertRaisesRegex(ExtractionError,"not bound"):
            self.verify("callback-tail-callee")

    def test_code_length_integer_required(self):
        obj=self.saved["callback-tail-callee"]
        obj["parameters"]["length"]="192"
        self.write_bytes("callback-tail-callee")
        with self.assertRaisesRegex(ExtractionError,"request identity"):
            self.verify("callback-tail-callee")

    def test_xref_result_bounded(self):
        p=self.path_refs("callback-tail-callee")
        obj=json.loads(p.read_text())
        obj["normalized_result"]=["0x2050"]*(audit.MAX_XREFS+1)
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ExtractionError,"Malformed"):
            self.full()

    def test_detailed_report_does_not_promote_root(self):
        s=audit.markdown(self.full())
        self.assertIn("No actual output allocation",s)
        self.assertIn("0x26bc",s)
        self.assertIn("0x25d8",s)
        self.assertIn("0x3d04",s)


# Each test flips ONE different bit from the first 64 bytes, in ONE specific
# original Ghidra imported callee. This checks byte-level firmware identity.
# 3 * 64 * 8 = 1536 separate mutated-input cases.
for role,_,_,_ in audit.WINDOWS:
    for at in range(64):
        for bit in range(8):
            def make(label,offset,bit_index):
                def test(self):
                    obj=self.saved[label]
                    original=bytearray.fromhex(obj["normalized_result"]["bytes_hex"])
                    original[offset]^=1<<bit_index
                    obj["normalized_result"]["bytes_hex"]=original.hex()
                    self.write_bytes(label)
                    with self.assertRaisesRegex(ExtractionError,
                                                "disagree"):
                        self.verify(label)
                return test
            setattr(CalleeEvidenceTests,
                    f"test_{role.replace('-','_')}_byte_{at:02d}_bit_{bit}",
                    make(role,at,bit))


if __name__=="__main__":
    unittest.main()
