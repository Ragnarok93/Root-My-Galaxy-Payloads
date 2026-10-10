#!/usr/bin/env python3
"""UEFI AllocatePool/FreePool/strnlen source-verified ARM64 tests.

The same 0x25d8 original source contains both 0x25d8 AllocatePool and
0x2618 EfiBootServicesData wrapper, to guard against cross-window alias
drift. Each semantic opcode undergoes 4 independent 32-bit mutation
families (bit flip; adjacent bits; distance-7; distance-13).
The dynamic tests do NOT claim that a synthetically mutated image is
a genuine original firmware image: original digest & Ghidra binding are
checked separately by the live analyzer.
"""
from __future__ import annotations

import hashlib
import struct
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_envdxe_efi_pool_ownership as impl
from tools.y2q_hxl1_extract_envdxe import ExtractionError

SIZES={
    "secondary-ram-helper":(0x25d8,160),
    "callback-tail-callee":(0x26bc,192),
    "record-copy-subroutine":(0x3d04,160),
}

def test_cb():
    return {
        "originalEnvDxeSha256":impl.PE_SHA256,
        "runtimePhysicalRamKnown":False,
        "kernelPhysicalLoadKnown":False,
        "exploitOrRootAchieved":False,
        "threeOriginalGhidraReadbacks":{"originalSha256":"verified_original_callback"},
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


def source_records():
    result=[]
    for key,(base,size) in SIZES.items():
        data=bytearray(size)
        for role,label in impl.SOURCE_NAMES.items():
            if label==key:
                for at,word in impl.WRAPPER_WORDS[role].items():
                    struct.pack_into("<I",data,at-base,word)
        required=set()
        for role,label in impl.SOURCE_NAMES.items():
            if label==key:
                required.update(impl.REQUIRED_XREF_SITES[role])
        result.append({
            "role":key,
            "originalExecutable":{
                "staticAddress":hex(base),
                "size":size,
                "bytesHex":bytes(data).hex(),
                "sha256":hashlib.sha256(data).hexdigest(),
            },
            "importedOriginalGhidraCode":{
                "match":True,
                "evidenceId":"ev_"+key,
            },
            "staticXrefs":{"sources":sorted(required)},
        })
    return result


class PoolSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.callee={
            "originalEnvDxeSha256":impl.PE_SHA256,
            "liveRamPartitionsMeasured":False,
            "additionalOriginalTargetReadbacks":source_records(),
        }
        self.cb=test_cb()

    def evaluate(self):
        with patch.object(impl,"source_report",return_value=self.callee):
            with patch.object(impl,"callback_report",return_value=self.cb):
                return impl.validate_sources(None)

    def mutate_instruction(self,role,addr,newword):
        source=impl.SOURCE_NAMES[role]
        item=next(x for x in self.callee["additionalOriginalTargetReadbacks"]
                  if x["role"]==source)
        s=item["originalExecutable"]
        blob=bytearray.fromhex(s["bytesHex"])
        struct.pack_into("<I",blob,addr-int(s["staticAddress"],16),newword)
        s["bytesHex"]=blob.hex()

    def test_correlated_pool_allocate_and_free_addresses(self):
        result=self.evaluate()
        self.assertEqual(result["bootServicesAllocatePoolOffset"],"0x40")
        self.assertEqual(result["bootServicesFreePoolOffset"],"0x48")
        self.assertEqual(result["allocatedMemoryTypeValue"],4)
        self.assertEqual(result["allocatedMemoryTypeName"],"EfiBootServicesData")

    def test_original_callback_pool_lifecycle(self):
        result=self.evaluate()
        self.assertEqual(result["callbackReusesEfiPoolAllocatorAt"],"0x1ff0")
        self.assertEqual(result["internalRamTableHelperCalledAt"],"0x2004")
        self.assertEqual(result["callbackFreesTemporaryEfiPoolAt"],"0x2050")
        self.assertFalse(result["actualRuntimeAllocationObserved"])
        self.assertFalse(result["actualRuntimeFreeObserved"])

    def test_string_length_not_record_copy(self):
        result=self.evaluate()
        self.assertTrue(result["boundedStringLengthNotPartitionCopy"])
        self.assertEqual(result["recordConversionRemainsInCallbackAt"],"0x2030-0x2040")
        self.assertIn("NOT RAM record copy",result["authenticatedSourceRoles"]
                      ["bounded-string-length"]["sourceNameCorrected"])

    def test_render_documents_pool_lifecycle_and_limits(self):
        report=impl.markdown(self.evaluate())
        self.assertIn("0x25d8",report)
        self.assertIn("0x26bc",report)
        self.assertIn("0x3d04",report)
        self.assertIn("No SMEM",report) if "No SMEM" in report else self.assertIn(
            "DRAM table values",report)

    def test_all_27_exact_arm64_words_check(self):
        result=self.evaluate()
        verified=sum(x["opcodeCount"] for x in result["authenticatedSourceRoles"].values())
        self.assertEqual(verified,27)
        self.assertEqual(len(result["authenticatedSourceRoles"]),4)

    def test_missing_allocated_original_sha_rejected(self):
        self.callee["originalEnvDxeSha256"]="bad"
        with self.assertRaisesRegex(ExtractionError,"source evidence or runtime proof boundary"):
            self.evaluate()

    def test_false_runtime_root_claim_rejected(self):
        self.cb["exploitOrRootAchieved"]=True
        with self.assertRaisesRegex(ExtractionError,"source evidence or runtime proof boundary"):
            self.evaluate()

    def test_missing_original_ghidra_attestation_rejected(self):
        self.callee["additionalOriginalTargetReadbacks"][1]["importedOriginalGhidraCode"]=None
        with self.assertRaisesRegex(ExtractionError,"attestations missing"):
            self.evaluate()

    def test_missing_original_xrefs_rejected(self):
        self.callee["additionalOriginalTargetReadbacks"][2]["staticXrefs"]=None
        with self.assertRaisesRegex(ExtractionError,"attestations missing"):
            self.evaluate()

    def test_missing_freepool_caller_rejected(self):
        item=next(x for x in self.callee["additionalOriginalTargetReadbacks"]
                  if x["role"]=="callback-tail-callee")
        item["staticXrefs"]["sources"]=[]
        with self.assertRaisesRegex(ExtractionError,"references changed"):
            self.evaluate()

    def test_wrong_callback_free_target_rejected(self):
        self.cb["cfg"]["reachableCalls"][-1]["target"]="0x1234"
        with self.assertRaisesRegex(ExtractionError,"lost allocator/free"):
            self.evaluate()

    def test_outside_original_elf_range_rejected(self):
        role="allocate-pool"
        blob=bytes.fromhex(next(x for x in self.callee["additionalOriginalTargetReadbacks"]
                  if x["role"]=="secondary-ram-helper")["originalExecutable"]["bytesHex"])
        with self.assertRaisesRegex(ExtractionError,"outside original executable"):
            impl.word_at(blob,0x25d8,0x1fa4)

    def test_corrupt_shared_allocator_affects_type4_source(self):
        self.mutate_instruction("allocate-pool",0x25f0,0xd503201f)
        with self.assertRaisesRegex(ExtractionError,"opcode mismatch"):
            self.evaluate()

    def test_corrupt_strnlen_reader_not_accepted_as_copy(self):
        self.mutate_instruction("bounded-string-length",0x3d34,0xd503201f)
        with self.assertRaisesRegex(ExtractionError,"opcode mismatch"):
            self.evaluate()

    def test_no_actual_dram_values_promoted(self):
        self.assertFalse(self.evaluate()["runtimeRamTableObserved"])
        self.assertFalse(self.evaluate()["kernelPhysicalLoadObserved"])
        self.assertFalse(self.evaluate()["rootOrKernelSUInstalled"])


def make_test(role,at,bit,family):
    orig=impl.WRAPPER_WORDS[role][at]
    positions=[bit]
    if family=="adjacent":
        positions.append((bit+1)%32)
    elif family=="seventh":
        positions.append((bit+7)%32)
    elif family=="thirteenth":
        positions.append((bit+13)%32)
    mutated=orig
    for p in positions:
        mutated^=1<<p
    def test(self):
        self.mutate_instruction(role,at,mutated)
        with self.assertRaisesRegex(ExtractionError,"opcode mismatch"):
            self.evaluate()
    return test


# 27 distinct original opcodes * 32 bits * 4 families = 3456 cases.
for role,words in impl.WRAPPER_WORDS.items():
    for at in words:
        for bit in range(32):
            for family in ("single","adjacent","seventh","thirteenth"):
                setattr(PoolSemanticsTests,
                        f"test_{role.replace('-','_')}_{at:04x}_{family}_{bit:02d}",
                        make_test(role,at,bit,family))


if __name__=="__main__":
    unittest.main()
