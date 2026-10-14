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

    def test_terminal_control_transfer_is_explicit_not_inferred(self):
        result=self.run_block()
        self.assertEqual(result["terminalControlTransfer"]["opcode"],"ret")
        self.assertTrue(result["terminalControlTransfer"]["observedTerminator"])
        self.assertEqual(result["immediateSuccessorBlocks"],[])
        self.assertFalse(result["allRuntimePathsVerified"])

    def test_one_hop_conditional_successors_are_separate_windows(self):
        code=make_code()
        branch=BASE+0xb90
        code[TARGET+8]=("b.eq",hex(branch))
        code[TARGET+12]=("mov","x1, x2")
        code[TARGET+16]=("ret","")
        code[branch]=("bl",hex(CALLEE))
        code[branch+4]=("ret","")
        result=self.run_block(code)
        successors=result["immediateSuccessorBlocks"]
        self.assertEqual(len(successors),2)
        self.assertEqual({x["relativeToDoFutexEntry"] for x in successors},
                         {"0xb2c","0xb90"})
        self.assertEqual(result["oneHopSuccessorDirectCalls"],1)
        self.assertTrue(all(x["dynamicPathFeasibilityVerified"] is False for x in successors))
        self.assertFalse(result["interproceduralPointerDataflowVerified"])

    def test_unconditional_branch_successor_does_not_follow_third_block(self):
        code=make_code()
        branch=BASE+0xb90
        code[TARGET+8]=("b",hex(branch))
        code[branch]=("b",hex(BASE+0xba0))
        code[BASE+0xba0]=("bl",hex(CALLEE))
        code[BASE+0xba4]=("ret","")
        result=self.run_block(code)
        self.assertEqual(len(result["immediateSuccessorBlocks"]),1)
        self.assertEqual(result["oneHopSuccessorDirectCalls"],0)
        self.assertEqual(result["immediateSuccessorBlocks"][0]["instructionSlots"],1)
        self.assertEqual(result["immediateSuccessorBlocks"][0]["stopReason"],
                         "STOPPED_AT_CONTROL_TRANSFER")

    def test_branch_to_first_block_is_not_recursively_followed(self):
        code=make_code()
        code[TARGET+8]=("b",hex(TARGET))
        result=self.run_block(code)
        self.assertEqual(result["immediateSuccessorBlocks"][0]["status"],
                         "CYCLE_TO_FIRST_BLOCK_NOT_FOLLOWED")
        self.assertEqual(result["oneHopSuccessorDirectCalls"],0)

    def test_no_successor_when_first_block_truncated_at_archive_boundary(self):
        code=make_code()
        code.pop(TARGET+8)
        result=self.run_block(code)
        self.assertEqual(result["stopReason"],
                         "STOPPED_AT_RECOVERED_FUNCTION_WINDOW_BOUNDARY")
        self.assertFalse(result["terminalControlTransfer"]["observedTerminator"])
        self.assertEqual(result["immediateSuccessorBlocks"],[])

    def test_depth_two_follows_only_static_two_hop_branches(self):
        code=make_code()
        first=BASE+0xb90
        second_a=BASE+0xba0
        second_b=BASE+0xbb0
        code[TARGET+8]=("b.eq",hex(first))
        code[TARGET+12]=("b",hex(second_a))
        code[first]=("b",hex(second_b))
        code[second_a]=("bl",hex(CALLEE))
        code[second_a+4]=("ret","")
        code[second_b]=("bl",hex(CALLEE))
        code[second_b+4]=("ret","")
        result=self.run_block(code)
        self.assertEqual(result["oneHopSuccessorDirectCalls"],0)
        self.assertEqual(result["twoHopDirectCalls"],2)
        self.assertEqual([x["relativeToDoFutexEntry"]
                          for x in result["twoHopSuccessorBlocks"]],
                         ["0xba0","0xbb0"])
        self.assertTrue(all(x["sourceLocalWaiterIdentityVerified"] is False
                            for x in result["twoHopSuccessorBlocks"]))
        self.assertFalse(result["allRuntimePathsVerified"])

    def test_depth_two_cycles_not_followed_recursively(self):
        code=make_code()
        code[TARGET+8]=("b",hex(BASE+0xb90))
        code[BASE+0xb90]=("b",hex(TARGET))
        result=self.run_block(code)
        self.assertEqual(len(result["immediateSuccessorBlocks"]),1)
        self.assertEqual(result["twoHopSuccessorBlocks"],[])
        self.assertEqual(result["twoHopDirectCalls"],0)

    def test_depth_two_requires_terminated_first_successor(self):
        code=make_code()
        code[TARGET+8]=("b",hex(BASE+0xb90))
        for i in range(m.MAX_SUCCESSOR_INSTRUCTIONS):
            code[BASE+0xb90+i*4]=("nop","")
        code[BASE+0xb90+m.MAX_SUCCESSOR_INSTRUCTIONS*4]=("b",hex(BASE+0xf00))
        code[BASE+0xf00]=("bl",hex(CALLEE))
        result=self.run_block(code)
        self.assertEqual(result["immediateSuccessorBlocks"][0]["stopReason"],
                         "MAX_SUCCESSOR_BOUND")
        self.assertEqual(result["twoHopSuccessorBlocks"],[])
        self.assertEqual(result["twoHopDirectCalls"],0)

    def test_depth_two_produces_bounded_no_runtime_identity_claims(self):
        code=make_code()
        code[TARGET+8]=("b",hex(BASE+0xb90))
        code[BASE+0xb90]=("b",hex(BASE+0xbb0))
        code[BASE+0xbb0]=("bl",hex(CALLEE))
        code[BASE+0xbb4]=("ret","")
        result=self.run_block(code)
        depth2=result["twoHopSuccessorBlocks"]
        self.assertEqual(len(depth2),1)
        self.assertEqual(depth2[0]["instructionSlots"],2)
        self.assertFalse(depth2[0]["dynamicPathFeasibilityVerified"])
        self.assertFalse(depth2[0]["directCalls"][0][
            "effectiveCalleeOrWaiterSourceIdentityVerified"])
        self.assertEqual(result["maxOriginalBranchHopsInspected"],2)

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
