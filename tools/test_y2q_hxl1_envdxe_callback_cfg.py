#!/usr/bin/env python3
"""Tests the actual HXL1 callback's two reachable paths and record translation.

The 128-byte callback entry and 96-byte continuation samples below are exact
original PE/Ghidra-matched byte strings from the investigation report.
The final 20 bytes are synthetic here; the production audit independently
requires a new SHA-bound Ghidra read for those bytes.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_envdxe_callback_cfg as cfg
from tools.y2q_hxl1_extract_envdxe import ExtractionError

ENTRY=bytes.fromhex(
    "f50f1df8f44f01a9fd7b02a9fd830091b50080d2ff0700f9"
    "f40302aaf30301aa1500f0f2f40100b4e0230091e1031faa"
    "ca0c0094e80300aae0031faa1f0115eb21010054ea0740f9"
    "8b0240b95f010beb29010054e00315aa8a0200b902000014"
    "a00e00d1fd7b42a9f44f41a9f50743f8c0035fd64c0d0a8b"
    "80f17dd38a010094"
)
CONT=bytes.fromhex(
    "4c0d0a8b80f17dd38a010094f40300aaf40000b4e0230091"
    "e10314aab20c0094a00000b4e00b41b2f2ffff17a0120091"
    "f0ffff17e90740f9e8031faa6a2200918ba2009106000014"
    "6d815ff8080500914d811ff86e8544f84e0501f81f0109eb"
)
assert len(ENTRY)==128 and len(CONT)==96
assert ENTRY[-12:]==CONT[:12]


def raw_fixture():
    # Ending body is unverified synthetic filler solely for CFG unit tests.
    data=ENTRY+CONT[12:]+(struct.pack("<I",0xd65f03c0)*5)
    assert len(data)==cfg.END-cfg.BASE
    return data


def existing_parent():
    return {
        "originalEnvDxeSha256":cfg.PE_SHA256,
        "bootTimeRamTableValuesMeasured":False,
        "rootPrivilegeDemonstrated":False,
        "targetedXrefs":[{
            "label":"post-callback-code",
            "references":["0x1fc4"],"target":"0x1fe8",
        }],
    }


class CallbackContinuationTests(unittest.TestCase):
    def setUp(self):
        self.raw=raw_fixture()
        self.earlier=existing_parent()
        self.folder=Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree,self.folder)

    def audit(self):
        with patch.object(cfg,"helper_audit",return_value=self.earlier):
            with patch.object(cfg,"full_bytes",return_value=(
                self.raw,{
                    "originalSha256":"synthetic",
                    "firstRead":"ev_a",
                    "continuationRead":"ev_b",
                    "finalTail":{"evidenceId":"ev_c","originalBytesMatchGhidra":True},
                    "continuousOriginalAndImportedCoverage":True,
                },
            )):
                return cfg.analyze(self.folder)

    def test_branch_bypasses_return_into_continuation(self):
        x=self.audit()
        self.assertEqual(x["observedIntraCallbackContinuation"],
                         "0x1fc4 -> 0x1fe8")
        self.assertTrue(x["retAt1fe4IsOnlyOnePath"])
        reach=x["cfg"]["reachableInstructionAddresses"]
        self.assertIn("0x1fe4",reach)
        self.assertIn("0x1fe8",reach)
        self.assertIn("0x2044",reach)

    def test_all_four_getram_paths_statically_reachable(self):
        calls={x["pc"]:x["target"] for x in self.audit()["cfg"]["reachableCalls"]}
        self.assertEqual(calls["0x1fa4"],"0x52cc")
        self.assertEqual(calls["0x1ff0"],"0x2618")
        self.assertEqual(calls["0x2004"],"0x52cc")

    def test_72_byte_internal_stride_and_16_byte_output(self):
        x=self.audit()
        transfer=x["recordTransferStaticEvidence"]
        self.assertEqual(transfer["internalRecordStrideBytes"],72)
        self.assertEqual(transfer["externalOutputStrideBytes"],16)
        self.assertTrue(transfer["twoUint64FieldsCopiedPerOutputRecord"])
        self.assertFalse(transfer["runtimeValuesMeasured"])

    def test_no_physical_or_root_promotions(self):
        x=self.audit()
        self.assertFalse(x["runtimePhysicalRamKnown"])
        self.assertFalse(x["kernelPhysicalLoadKnown"])
        self.assertFalse(x["exploitOrRootAchieved"])
        self.assertFalse(x["boundaryGhidraFunctionVerified"])
        self.assertFalse(x["cfg"]["runtimeControlFlowMeasured"])

    def test_callback_does_not_terminate_at_first_ret(self):
        out=cfg.bounded_cfg(self.raw)
        reachable=out["reachableInstructionAddresses"]
        self.assertLess(reachable.index("0x1fe4"),reachable.index("0x1fe8"))
        self.assertIn("0x1ff0",reachable)

    def test_static_cfg_tracks_out_of_window_successors(self):
        word=struct.pack("<I",0x14000002) # from base to base+8
        raw=word+struct.pack("<I",0xd65f03c0)*2
        x=cfg.bounded_cfg(raw,0x1000)
        self.assertEqual(x["reachableInstructionAddresses"],["0x1000","0x1008"])
        self.assertEqual(x["returnsAndUnresolvedIndirectJumps"],
                         [{"pc":"0x1008","kind":"RET"}])

    def test_b_cond_both_edges_visited(self):
        # B.cond +8 (from instruction 0x1000)
        raw=struct.pack("<I",0x54000040)+struct.pack("<I",0xd65f03c0)*2
        x=cfg.bounded_cfg(raw,0x1000)
        self.assertIn("0x1004",x["reachableInstructionAddresses"])
        self.assertIn("0x1008",x["reachableInstructionAddresses"])

    def test_bl_fallthrough_but_does_not_enter_external_callee(self):
        raw=struct.pack("<II",0x94000100,0xd65f03c0)
        x=cfg.bounded_cfg(raw,0x1000)
        self.assertEqual(x["reachableInstructionAddresses"],["0x1000","0x1004"])
        self.assertEqual(x["reachableCalls"][0]["target"],"0x1400")

    def test_conditional_branch_can_reenter_before_ret(self):
        raw=struct.pack("<III",0x54000040,0xd65f03c0,0x17ffffff)
        x=cfg.bounded_cfg(raw,0x1000)
        self.assertEqual(len(x["reachableInstructionAddresses"]),3)
        self.assertEqual(x["reachableDirectBranches"][0]["target"],"0x1008")

    def test_reject_unaligned_body(self):
        with self.assertRaisesRegex(ExtractionError,"aligned"):
            cfg.bounded_cfg(b"\0"*11,0x1000)

    def test_reject_unaligned_entry(self):
        with self.assertRaisesRegex(ExtractionError,"aligned"):
            cfg.bounded_cfg(b"\0"*16,0x1002)

    def test_reject_empty_body(self):
        with self.assertRaisesRegex(ExtractionError,"nonempty"):
            cfg.bounded_cfg(b"",0x1000)

    def test_missing_original_xref_rejected(self):
        self.earlier["targetedXrefs"][0]["references"]=[]
        with self.assertRaisesRegex(ExtractionError,"corroborate"):
            self.audit()

    def test_reject_boot_time_ram_promotion(self):
        self.earlier["bootTimeRamTableValuesMeasured"]=True
        with self.assertRaisesRegex(ExtractionError,"promotes"):
            self.audit()

    def test_reject_parent_root_promotion(self):
        self.earlier["rootPrivilegeDemonstrated"]=True
        with self.assertRaisesRegex(ExtractionError,"promotes"):
            self.audit()

    def test_reject_wrong_source_sha(self):
        self.earlier["originalEnvDxeSha256"]="f"*64
        with self.assertRaisesRegex(ExtractionError,"promotes"):
            self.audit()

    def test_render_calls_visible(self):
        md=cfg.markdown(self.audit())
        self.assertIn("0x1ff0",md)
        self.assertIn("0x2004",md)
        self.assertIn("16-byte LinuxLoader",md)

    def test_final_window_not_a_guaranteed_function_boundary(self):
        x=self.audit()
        self.assertEqual(x["callbackProvisionalExclusiveBoundary"],"0x205c")
        self.assertFalse(x["boundaryGhidraFunctionVerified"])

    def test_arm64_b_cond_exact_branch(self):
        edges=cfg.arm64_edges(self.raw,cfg.BASE)
        a=next(x for x in edges if x["instructionAddress"]=="0x1fc4")
        self.assertEqual(a["directBranchTarget"],"0x1fe8")
        self.assertEqual(a["mnemonicClass"],"B.cond")

    def test_pasted_real_entry_and_tail_overlap_exactly(self):
        self.assertEqual(ENTRY[-12:],CONT[:12])
        self.assertEqual(self.raw[0x1fe8-cfg.BASE:0x2048-cfg.BASE],CONT)

    def test_unresolved_source_exits_are_reported_not_promoted(self):
        out=cfg.bounded_cfg(struct.pack("<I",0x14000002),0x1000)
        self.assertIn("0x1008",out["outOfWindowSuccessors"])
        self.assertFalse(out["completeGhidraFunctionVerified"])


# Each mutation of the 8 original ARM64 record-transfer instructions must
# independently reject semantic promotion even though original images are
# controlled (the external original SHA/gated REA checks are separate).
for address in cfg.RECORD_WORDS:
    for bit in range(32):
        def mk(at,n):
            def test(self):
                mutated=bytearray(self.raw)
                off=at-cfg.BASE
                current=struct.unpack_from("<I",mutated,off)[0]
                struct.pack_into("<I",mutated,off,current^(1<<n))
                self.raw=bytes(mutated)
                with self.assertRaises(ExtractionError):
                    self.audit()
            return test
        setattr(CallbackContinuationTests,
                f"test_record_opcode_{address:04x}_bit_{bit:02d}",mk(address,bit))


# Six original direct branch instructions must independently fail closed if
# any bit of their original encoded instruction changes (branch identity
# versus source-verified control flow).
for address in cfg.REQUIRED_BRANCHES:
    for bit in range(32):
        def mk(at,n):
            def test(self):
                mutated=bytearray(self.raw)
                off=at-cfg.BASE
                current=struct.unpack_from("<I",mutated,off)[0]
                struct.pack_into("<I",mutated,off,current^(1<<n))
                self.raw=bytes(mutated)
                with self.assertRaises(ExtractionError):
                    self.audit()
            return test
        setattr(CallbackContinuationTests,
                f"test_branch_opcode_{address:04x}_bit_{bit:02d}",mk(address,bit))


if __name__=="__main__":
    unittest.main()
