"""Host-only fixture tests for compact factory-kernel SMC->fault GDB capture."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_qemu_compact_fault_regs as m

def sample(target="x21",ret=True,base=0):
    pc,op,_=m.TARGETS[target]
    first=(
        "HXL1_ENTRY_VALID PC=0x40080000 X0=0x48000000\n"
        "HXL1_SMC_PRE PC=0xffffff80080a5794 X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000\n"
        "0xffffff80080a5794:\t0xd4000003\n"
    )
    middle=("HXL1_SMC_NEXT_PC PC=0xffffff80080a5798 X0=0xffffffffffffffff\n" if ret else "")
    end=(f"HXL1_FAULT_PRE PC={hex(pc)} BASE={hex(base)} "
         "SP=0xffffff800abc0000 LR=0xffffff8008084000\n"
         f"{hex(pc)}:\t0x{op}\n")
    return first+middle+end

class CompactFaultRegisterTests(unittest.TestCase):
    def test_capture_x21_before_ldr_is_null_compatible(self):
        r=m.analyze_log(sample("x21",base=0),"x21")
        self.assertTrue(r["actualFaultInstructionReached"])
        self.assertTrue(r["preFaultBaseIsZero"])
        self.assertEqual(r["possibleAccessOffsetsBytes"],[0x58])
        self.assertEqual(r["effectiveAddressesIfExecuted"],["0x58"])
        self.assertFalse(r["dataAbortCausallyCausedBySmcProven"])

    def test_capture_x10_before_ldp_has_two_possible_effective_addresses(self):
        r=m.analyze_log(sample("x10",base=0),"x10")
        self.assertEqual(r["instructionSource"]["instruction"],"LDP_X_OFFSET")
        self.assertEqual(r["possibleAccessOffsetsBytes"],[0x10,0x18])
        self.assertEqual(r["effectiveAddressesIfExecuted"],["0x10","0x18"])
        self.assertFalse(r["subsequentDataAbortObservedInThisDebuggerRun"])

    def test_smc_next_pc_x0_is_not_secure_monitor_success(self):
        r=m.analyze_log(sample("x21"),"x21")
        self.assertTrue(r["smcNextPcObserved"])
        self.assertEqual(r["smcNextPcX0"],"0xffffffffffffffff")
        self.assertEqual(r["smcReturnStatusInterpretation"],"RAW_REGISTER_OBSERVATION_ONLY")
        self.assertFalse(r["smcServiceHandledSuccessfully"])

    def test_fault_base_read_without_return_pc_still_proven(self):
        r=m.analyze_log(sample("x21",ret=False),"x21")
        self.assertTrue(r["actualFaultInstructionReached"])
        self.assertFalse(r["smcNextPcObserved"])
        self.assertFalse(r["smcServiceHandledSuccessfully"])

    def test_missing_smc_opcode_rejected(self):
        r=m.analyze_log(sample().replace("0xd4000003","0xd503201f"),"x21")
        self.assertEqual(r["status"],"SMC_LIVE_PRE_OPCODE_OR_ARGUMENT_MISMATCH")
        self.assertFalse(r["actualFaultInstructionReached"])

    def test_original_smc_abi_id_cannot_change_silently(self):
        r=m.analyze_log(sample().replace("X1=0x15","X1=0x16"),"x21")
        self.assertEqual(r["status"],"SMC_LIVE_PRE_OPCODE_OR_ARGUMENT_MISMATCH")

    def test_fault_live_opcode_mismatch_rejected(self):
        r=m.analyze_log(sample().replace("0xf9402eb8","0xd503201f"),"x21")
        self.assertEqual(r["status"],"FAULT_PC_OR_LIVE_OPCODE_MISMATCH")

    def test_fault_live_pc_mismatch_rejected(self):
        r=m.analyze_log(sample().replace("PC=0xffffff80082ac90c","PC=0xffffff80082ac910"),"x21")
        self.assertEqual(r["status"],"FAULT_PC_OR_LIVE_OPCODE_MISMATCH")

    def test_no_smc_stage_never_accepts_fault(self):
        raw=sample().replace("HXL1_SMC_PRE","HXL1_OLD_SMC_PRE")
        self.assertFalse(m.analyze_log(raw,"x21")["actualFaultInstructionReached"])

    def test_entry_fdt_pointer_wrong_never_accepts_fault(self):
        raw=sample().replace("X0=0x48000000","X0=0x48001000")
        self.assertEqual(m.analyze_log(raw,"x21")["status"],"ORIGINAL_ENTRY_INCONCLUSIVE")

    def test_fault_absent_remains_inconclusive(self):
        raw=sample().split("HXL1_FAULT_PRE")[0]+"GDB_BOUNDED_TIMEOUT\n"
        r=m.analyze_log(raw,"x21")
        self.assertEqual(r["status"],"NO_FAULT_LOAD_BREAKPOINT_AFTER_SMC")
        self.assertFalse(r["actualFaultInstructionReached"])

    def test_gdb_stage_order_and_no_memory_write(self):
        for target in m.TARGETS:
            s=m.script(12353,target)
            self.assertLess(s.index("hbreak *0x40080000"),s.index("hbreak *0xffffff80080a5794"))
            self.assertIn(f"hbreak *{hex(m.TARGETS[target][0])}",s)
            self.assertIn("HXL1_FAULT_PRE",s)
            self.assertIn("x/1wx $pc",s)
            self.assertNotIn("set {",s)
            self.assertNotIn("restore ",s)

    def test_stop_guard_and_no_real_device_operation(self):
        source=Path(m.__file__).read_text()
        self.assertIn("proc.terminate()",source)
        self.assertIn("proc.kill()",source)
        self.assertIn('"-nic","none"',source)
        for phrase in ("adb shell","fastboot flash","cpu_physical_memory_write"):
            self.assertNotIn(phrase,source)

    def test_help_without_import_from_current_checkout(self):
        with tempfile.TemporaryDirectory() as t:
            p=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                             cwd=t,capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn("--target",p.stdout)
        self.assertIn("--preflight-only",p.stdout)

if __name__=="__main__":
    unittest.main()
