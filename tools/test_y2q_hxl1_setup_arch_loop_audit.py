"""No-QEMU regression tests for original-HXL1 setup_arch PC/callee tracing."""
from __future__ import annotations
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_setup_arch_loop_audit as a

PC=a.VM_BASE+0x200
CALLEE=a.VM_BASE+0x800
STRING=a.VM_BASE+0x450

def words():
    image=bytearray(b"\0"*0xa00)
    def put(va,n):image[va-a.VM_BASE:va-a.VM_BASE+4]=n.to_bytes(4,"little")
    put(PC-0x1c,0x1400000c)
    put(PC-0x18,0x90000000) # ADRP x0, current page
    put(PC-0x10,0x91000000 | (0x450<<10)) # ADD x0, x0, #0x450
    put(PC-8,0x94000000 | (((CALLEE-(PC-8))//4)&0x3ffffff))
    put(PC-4,a.YIELD_WORD)
    put(PC,a.B_PREV_WORD)
    put(CALLEE,0xd65f03c0) # ret, synthetic caller for symbol mapping
    image[0x450:0x450+20]=b"check sample string\0"
    return bytes(image)

def symbols():
    return {"status":"RECOVERED_NM_SYMBOLS_UNVERIFIED",
        "sourceSha256":"synthetic",
        "entries":[(a.VM_BASE+0x100,"T","setup_arch"),
                   (CALLEE,"T","synthetic_print_function")]}

class SetupArchLoopAuditTests(unittest.TestCase):
    def test_verified_yield_backward_branch(self):
        r=a.interpret(words(),PC,symbols())
        self.assertTrue(r["sourceContainsYieldBackwardBranchLoop"])
        self.assertEqual(r["branch"]["target"],hex(PC-4))
        self.assertEqual(r["classification"],
                         "PINNED_FACTORY_SOURCE_YIELD_LOOP_MATCHES_REPEATED_QMP_PC")
        self.assertFalse(r["loopRunningIndefinitelyProven"])

    def test_bl_and_callee_symbol_source_only(self):
        r=a.interpret(words(),PC,symbols())
        self.assertEqual(r["callee"]["target"],hex(CALLEE))
        self.assertEqual(r["callee"]["nearestRecoveredSymbol"]["name"],
                         "synthetic_print_function")
        self.assertFalse(r["callee"]["symbolNameValidatedByExecution"])

    def test_adrp_add_static_string(self):
        r=a.interpret(words(),PC,symbols())
        self.assertEqual(r["staticAddressSequence"]["candidateX0Address"],hex(STRING))
        self.assertEqual(r["staticAddressSequence"]["candidateImageString"]["value"],
                         "check sample string")
        self.assertIn("NOT_RUNTIME_GUEST",
                      r["staticAddressSequence"]["candidateImageString"]["proof"])

    def test_non_adrp_refuses_guessed_string(self):
        buf=bytearray(words());buf[PC-a.VM_BASE-0x18:PC-a.VM_BASE-0x14]=b"\0"*4
        r=a.interpret(bytes(buf),PC,symbols())
        self.assertFalse(r["staticAddressSequence"]["candidateAddressEstablished"])
        self.assertNotIn("candidateX0Address",r["staticAddressSequence"])

    def test_invalid_add_register_pair_refused(self):
        buf=bytearray(words())
        off=PC-a.VM_BASE-0x10
        word=int.from_bytes(buf[off:off+4],"little")
        buf[off:off+4]=(word|1).to_bytes(4,"little")
        r=a.interpret(bytes(buf),PC,symbols())
        self.assertFalse(r["staticAddressSequence"]["candidateAddressEstablished"])

    def test_yield_opcode_mutation_disables_loop(self):
        buf=bytearray(words())
        off=PC-a.VM_BASE-4
        buf[off:off+4]=(0xd503201f).to_bytes(4,"little") # nop, not yield
        r=a.interpret(bytes(buf),PC,symbols())
        self.assertFalse(r["sourceContainsYieldBackwardBranchLoop"])
        self.assertEqual(r["classification"],
                         "NO_VERIFIED_FACTORY_YIELD_LOOP_AT_SAMPLED_PC")

    def test_branch_outside_loop_not_a_loop(self):
        buf=bytearray(words())
        off=PC-a.VM_BASE
        buf[off:off+4]=(0x14000001).to_bytes(4,"little")
        r=a.interpret(bytes(buf),PC,symbols())
        self.assertFalse(r["sourceContainsYieldBackwardBranchLoop"])

    def test_skip_branch_source_edge_not_predecessor_condition(self):
        r=a.interpret(words(),PC,symbols())
        self.assertTrue(r["skipOverLoopBranch"]["skipsLoopBlock"])
        self.assertFalse(r["skipOverLoopBranch"]["branchPredecessorConditionProven"])

    def test_adrp_pc_relative_sign_extended(self):
        # Matches independently owner-observed 0xf0ffdb60 and VA.
        pc=0xffffff800a605134
        result=a.decode_adrp(0xf0ffdb60,pc)
        self.assertEqual(result["address"],0xffffff800a174000)
        self.assertEqual(result["reg"],0)

    def test_owner_add_x0_imm_matches_disassembly(self):
        op=0x91057000
        d=a.decode_add_imm(op)
        self.assertEqual(d["status"],"ADD64_IMMEDIATE")
        self.assertEqual((d["rd"],d["rn"],d["immediate"]),(0,0,0x15c))

    def test_ascii_requires_nul_and_printable(self):
        self.assertEqual(a.candidate_printable_string(words(),STRING,3)["status"],
                         "STRING_NOT_TERMINATED_WITHIN_BOUND")
        self.assertEqual(a.candidate_printable_string(words(),a.VM_BASE+0xfff)["status"],
                         "POINTER_OUTSIDE_FACTORY_IMAGE")
        self.assertEqual(a.candidate_printable_string(b"\x01\0",a.VM_BASE)["status"],
                         "NO_PLAUSIBLE_PRINTABLE_STRING")

    def test_prior_owner_report_gated_to_sample_pc(self):
        record={"target":a.prev.TARGET,
                "factoryImageSha256":a.gate.KERNEL_SHA,
                "sampledPc":hex(a.LOOP_PC),
                "originalImage":{"originalOpcode":"17ffffff"},
                "sourceQmpMode":"v3-canary","sampleCount":4}
        with self.assertRaises(a.LoopAuditError):
            a.read_prior_report(record,words(),symbols())

    def test_linux_printk_kern_soh_format_with_newlines(self):
        sample=bytearray(words())
        off=STRING-a.VM_BASE
        data=b"\x013\nError: invalid device tree blob: size=%d\\nPlease check your bootloader.\n\0"
        sample[off:off+len(data)]=data
        decoded=a.candidate_printk_format(bytes(sample),STRING)
        self.assertEqual(decoded["status"],"CANDIDATE_ORIGINAL_PRINTK_FORMAT")
        self.assertEqual(decoded["kernelSohLogLevelDigit"],"3")
        self.assertIn("check your bootloader",decoded["formatString"])
        self.assertIn("NOT_LIVE_PRINTK_OUTPUT",decoded["source"])

    def test_printk_rejects_invalid_control_and_missing_terminator(self):
        self.assertEqual(a.candidate_printk_format(b"\x01\x1fabc\0",a.VM_BASE)
                         ["status"],"INVALID_OR_NON_TEXT_PRINTK_FORMAT")
        self.assertEqual(a.candidate_printk_format(b"X"*32,a.VM_BASE,8)
                         ["status"],"NOT_NUL_TERMINATED_WITHIN_BOUND")

    def test_source_image_bytes_out_of_range_refused(self):
        with self.assertRaisesRegex(a.LoopAuditError,"not backed"):
            a.get_word(words(),a.VM_BASE+0x20000)

    def test_original_source_only_never_guest_writes(self):
        code=Path(a.__file__).read_text()
        for bad in ("fastboot flash","adb shell","qemu-system-aarch64",
                    "memory_write","cpu_physical_memory_write"):
            self.assertNotIn(bad,code)
        self.assertIn("gate.valid_source(image)",code)

    def test_cli_direct_help_in_isolated_python(self):
        with tempfile.TemporaryDirectory() as d:
            p=subprocess.run([sys.executable,"-I",str(Path(a.__file__)),"--help"],
                             cwd=d,capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn("--prior",p.stdout)

if __name__=="__main__":
    unittest.main()
