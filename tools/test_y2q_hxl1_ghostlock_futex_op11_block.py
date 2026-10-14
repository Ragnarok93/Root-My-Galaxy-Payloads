"""No-phone tests for SHA-gated original do_futex opcode-11 first-block audit."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_ghostlock_futex_op11_block as m

BASE=0xffffff8008080000
TARGET=BASE+0xb20
CALLEE=0xffffff80082af0e4

def make_code():
    return {
      BASE+0xb14:("cmp","w8, #0xb"),
      BASE+0xb18:("b.eq",hex(TARGET)),
      TARGET:("mov","x0, x1"),
      TARGET+4:("bl",hex(CALLEE)),
      TARGET+8:("ret",""),
    }
def syms():
    return {CALLEE:["__kmalloc"],CALLEE+0x100:["other"]}

class Op11FirstBlockTests(unittest.TestCase):
    def run_block(self,code=None,symbols=None):
        labels=symbols if symbols is not None else syms()
        return m.examine_op11(code if code is not None else make_code(),
                             BASE,labels,sorted(labels))

    def test_original_compare_and_branch_are_required(self):
        d=self.run_block()
        self.assertEqual(d["case11BlockStartRelativeToDoFutexEntry"],"0xb20")
        self.assertEqual(d["originalLinearInstructionSlotsReviewed"],3)
        self.assertEqual(d["stopReason"],"STOPPED_AT_EXPLICIT_CONTROL_TRANSFER")

    def test_exact_known_branch_target_label_not_runtime_claim(self):
        d=self.run_block()
        self.assertEqual(len(d["callTargetsInFirstBlock"]),1)
        x=d["callTargetsInFirstBlock"][0]
        self.assertEqual(x["recoveredTextTarget"]["status"],"EXACT_RECOVERED_TEXT_LABEL")
        self.assertEqual(x["recoveredTextTarget"]["labels"],["__kmalloc"])
        self.assertFalse(x["effectiveCalleeOrSourceIdentityVerified"])

    def test_source_local_waiter_stays_unidentified(self):
        d=self.run_block()
        self.assertFalse(d["compilerInlinedFutexWaitRequeuePiProven"])
        self.assertFalse(d["waiterSourceLocalMachineSlotIdentified"])
        self.assertFalse(d["branchTakenDynamicallyObserved"])

    def test_modified_opcode11_cmp_is_rejected(self):
        code=make_code()
        code[BASE+0xb14]=("cmp","w8, #0xc")
        with self.assertRaisesRegex(m.Stop,"compare"):
            self.run_block(code)

    def test_missing_branch_guard_rejected(self):
        code=make_code()
        code[BASE+0xb18]=("b.ne",hex(TARGET))
        with self.assertRaisesRegex(m.Stop,"dispatcher branch"):
            self.run_block(code)

    def test_jump_to_nonpresent_code_fails(self):
        code=make_code()
        code[BASE+0xb18]=("b.eq",hex(BASE+0xffff))
        with self.assertRaisesRegex(m.Stop,"outside bounded"):
            self.run_block(code)

    def test_early_control_transfer_is_a_stop_not_a_linear_path(self):
        code=make_code()
        code[TARGET]=("b",hex(BASE+0x1100))
        d=self.run_block(code)
        self.assertEqual(d["originalLinearInstructionSlotsReviewed"],1)
        self.assertEqual(len(d["callTargetsInFirstBlock"]),0)

    def test_immediate_control_loop_do_not_follow_other_basic_blocks(self):
        code=make_code()
        code[TARGET+8]=("b.eq",hex(TARGET))
        d=self.run_block(code)
        self.assertEqual(d["originalLinearInstructionSlotsReviewed"],3)
        self.assertEqual(d["stopReason"],"STOPPED_AT_EXPLICIT_CONTROL_TRANSFER")

    def test_missing_branch_target_safely_bounded(self):
        code=make_code()
        code.pop(TARGET+8)
        d=self.run_block(code)
        self.assertEqual(d["stopReason"],"STOPPED_AT_RECOVERED_FUNCTION_WINDOW_BOUNDARY")

    def test_synthetic_big_linear_block_has_cap(self):
        code=make_code()
        code.pop(TARGET+8)
        for i in range(128):
            code[TARGET+i*4]=("nop","")
        d=self.run_block(code)
        self.assertEqual(d["originalLinearInstructionSlotsReviewed"],m.MAX_BLOCK_INSTRUCTIONS)
        self.assertEqual(d["stopReason"],"MAX_LINEAR_WINDOW_REACHED")

    def test_unmatched_indirect_call_is_not_guessed(self):
        code=make_code()
        code[TARGET+4]=("blr","x8")
        d=self.run_block(code)
        self.assertEqual(len(d["callTargetsInFirstBlock"]),0)
        self.assertFalse(d["compilerInlinedFutexWaitRequeuePiProven"])

    def test_archive_original_sha_is_strict_pin(self):
        self.assertEqual(m.ARCHIVE_SHA,
          "20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997")

    def test_script_is_executable_from_external_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            proc=subprocess.run(
                [sys.executable,"-I",str(Path(m.__file__).resolve()),"--help"],
                cwd=directory,text=True,capture_output=True,timeout=15)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertIn("--archive",proc.stdout)
        self.assertNotIn("ModuleNotFoundError",proc.stderr)

if __name__=="__main__":
    unittest.main()
