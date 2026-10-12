"""Host-only original-Image attribution of repeated HXL1 QMP PC snapshots."""
from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_qemu_pc_attribution as a
from tools import y2q_hxl1_qemu_memblock_pc_sampler as q

PC=a.IMAGE_BASE+0x100

def image():
    data=bytearray(b"\0"*0x400)
    data[0x100:0x104]=(0x14000000).to_bytes(4,"little")  # b .
    data[0x190:0x1a0]=b"test factory\x00...."
    return bytes(data)

def sample(pc=PC,reg_x1=a.IMAGE_BASE+0x190,repeats=4):
    raw=(f"CPU#0\r\n PC={pc:016x} "
         f"X00=00000000000000cb X01={reg_x1:016x}\r\n"
         "X13=756f79206b636568 X14=6f6c746f6f622072\r\n"
         f"X16={pc-4:016x} X20=0000000048000000 "
         f"X30={pc-4:016x}\r\nPSTATE=600001c5 EL1h\r\n")
    samples=[{"index":i+1,"runStatus":"running","registers":{
        "pc":hex(pc),"pcMatches":1,"raw":raw,"rawTruncated":False
    }} for i in range(repeats)]
    return {
      "target":a.TARGET,
      "factorySha256":hashlib.sha256(image()).hexdigest(),
      "mode":"v3-canary",
      "status":q.classify(samples,"v3-canary")["status"],
      "samples":samples,"pcSequence":[hex(pc)]*repeats,
      "samplingError":None
    }

def sym():
    return {"status":"RECOVERED_NM_SYMBOLS_UNVERIFIED",
            "entries":[(a.IMAGE_BASE+0x80,"T","synthetic_test")],
            "sourceSha256":"synthetic"}

class QmpPcAttributionTests(unittest.TestCase):
    def build(self,document=None,original=None):
        orig=image() if original is None else original
        data=sample() if document is None else document
        with patch.object(a.gate,"KERNEL_SHA",hashlib.sha256(orig).hexdigest()):
            return a.build_report(data,orig,sym(),None,expected_pc=None)

    def test_stock_pc_and_nearest_symbol_reconstructed(self):
        r=self.build()
        self.assertEqual(r["sampledPc"],hex(PC))
        self.assertEqual(r["originalImage"]["candidateImageOffset"],"0x100")
        self.assertEqual(r["nearestRecoveredTextSymbol"]["name"],"synthetic_test")
        self.assertEqual(r["sourceQmpMode"],"v3-canary")
        self.assertTrue(r["allSampledPcsIdentical"])
        self.assertTrue(r["allRetainedGpRegistersIdentical"])
        self.assertFalse(r["actualGuestHangOrInfiniteLoopProven"])
        self.assertFalse(r["memblockAllocatorReservationProven"])

    def test_repeat_samples_contain_original_opcode_direct_self_branch(self):
        r=self.build()
        self.assertEqual(r["originalImage"]["originalOpcode"],"14000000")
        self.assertEqual(r["opcodeDirectBranch"]["kind"],"B")
        self.assertEqual(r["opcodeDirectBranch"]["target"],hex(PC))
        self.assertTrue(r["opcodeDirectBranch"]["directBranchToSelf"])
        self.assertFalse(r["liveGuestInstructionBytesMatched"])

    def test_registers_x16_x30_one_instruction_before_pc(self):
        r=self.build()
        for name in ("X16","X30"):
            self.assertEqual(
                r["nearbyBranchOrLinkRegisters"][name]["distanceFromPcBytes"],-4)

    def test_little_endian_ascii_fragments_do_not_infer_message(self):
        r=self.build()
        self.assertEqual(r["asciiRegisterFragments"]["X13"]["printableFragment"],
                         "heck you")
        self.assertEqual(r["asciiRegisterFragments"]["X14"]["printableFragment"],
                         "r bootlo")
        self.assertIn("not proof",r["asciiRegisterFragments"]["X13"]["warning"])

    def test_literal_string_pointer_only_from_pinned_factory_bytes(self):
        r=self.build()
        self.assertEqual(
            r["candidateOriginalImageStringsFromGpPointers"]["X01"]["value"],
            "test factory")
        self.assertIn("NOT_LIVE_GUEST_MEMORY",
                      r["candidateOriginalImageStringsFromGpPointers"]["X01"]["source"])

    def test_pointer_outside_original_image_not_accepted_as_string(self):
        r=self.build(sample(reg_x1=0xffffff800f000000))
        self.assertEqual(
            r["candidateOriginalImageStringsFromGpPointers"]["X01"]["status"],
            "NOT_BACKED_BY_ORIGINAL_IMAGE_FILE")

    def test_non_null_terminated_string_refused(self):
        assert a.candidate_ascii(b"ABCDEFGHIJK",a.IMAGE_BASE,limit=4)["status"]==(
            "NOT_NULL_TERMINATED_WITHIN_BOUND")

    def test_source_sha_mismatch_is_rejected(self):
        with self.assertRaisesRegex(a.gate.GateError,"SHA256 mismatch"):
            a.build_report(sample(),image(),sym(),None,expected_pc=None)

    def test_unrecognized_mode_and_target_rejected(self):
        for key,bad in (("target","other"),("mode","phone"),("factorySha256","0"*64)):
            v=sample();v[key]=bad
            with self.subTest(key=key),self.assertRaises(a.PcAttributionError):
                a.verify_sample_report(v)

    def test_raw_pc_tamper_rejected(self):
        v=sample()
        v["samples"][1]["registers"]["pc"]="0xffff000000001234"
        with self.assertRaisesRegex(a.PcAttributionError,"QMP PC inconsistent"):
            a.verify_sample_report(v)

    def test_raw_registers_must_be_complete_and_untruncated(self):
        v=sample()
        v["samples"][1]["registers"]["rawTruncated"]=True
        with self.assertRaisesRegex(a.PcAttributionError,"missing or truncated"):
            a.verify_sample_report(v)

    def test_sampled_pc_must_be_present_in_original_image(self):
        v=sample(pc=a.IMAGE_BASE+0x1000)
        with self.assertRaisesRegex(a.PcAttributionError,"outside original"):
            self.build(document=v)

    def test_owner_repeated_pc_guard_and_explicit_override(self):
        v=sample()
        with patch.object(a.gate,"KERNEL_SHA",hashlib.sha256(image()).hexdigest()):
            with self.assertRaisesRegex(a.PcAttributionError,"changed from expected"):
                a.build_report(v,image(),sym(),None,expected_pc=a.PC_FROM_OWNER_QMP)
        self.assertEqual(self.build(v)["sampledPc"],hex(PC))

    def test_ambiguous_pc_snapshot_rejected(self):
        v=sample()
        v["samples"][1]["registers"]["raw"]=v["samples"][1]["registers"]["raw"].replace(
            "CPU#0",f"CPU#0 PC={PC:016x}")
        with self.assertRaisesRegex(a.PcAttributionError,"PC inconsistent"):
            a.verify_sample_report(v)

    def test_nonbranch_and_negative_offset_branch(self):
        self.assertEqual(a.aarch64_unconditional_branch(0xd503201f,PC)["status"],
                         "NOT_A64_DIRECT_B_OR_BL")
        r=a.aarch64_unconditional_branch(0x17ffffff,PC)
        self.assertEqual(r["target"],hex(PC-4))
        self.assertFalse(r["directBranchToSelf"])

    def test_original_code_source_has_no_guest_memory_mutation(self):
        src=Path(a.__file__).read_text()
        for phrase in ("fastboot flash", "adb shell", "memory_write(",
                       "cpu_physical_memory_write", "qemu-system-aarch64"):
            self.assertNotIn(phrase,src)
        self.assertIn("gate.valid_source(image)",src)

    def test_cli_help_isolated_from_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([sys.executable,"-I",str(Path(a.__file__)), "--help"],
                             cwd=d,capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertIn("--report",r.stdout)
            self.assertIn("--allow-other-pc",r.stdout)

if __name__=="__main__":
    unittest.main()
