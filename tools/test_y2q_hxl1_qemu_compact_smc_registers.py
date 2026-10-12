"""No-guest tests for read-only HXL1 compact SMC GDB X0-X6 capture."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_qemu_compact_smc_registers as m


def valid_log():
    return (
        "Breakpoint 1, 0x40080000 in ?? ()\n"
        "HXL1_COMPACT_ENTRY_OK PC=0x40080000 X0=0x48000000 X1=0x0 X2=0x0 X3=0x0\n"
        "Breakpoint 2, 0xffffff80080a5794 in ?? ()\n"
        "HXL1_COMPACT_SMC_STOP PC=0xffffff80080a5794 X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000 X4=0x0 X5=0x0 X6=0x0\n"
        "0xffffff80080a5794:\t0xd4000003\n"
    )

class CompactSmcCaptureTests(unittest.TestCase):
    def test_verified_entry_then_smc_before_execution(self):
        r=m.analyze_log(valid_log())
        self.assertEqual(r["status"],"STOCK_SMC_0_LIVE_ARGUMENTS_CAPTURED")
        self.assertEqual(r["registerArguments"]["X0"],"0xc300c002")
        self.assertEqual(r["registerArguments"]["X1"],"0x15")
        self.assertTrue(r["smcCallArgumentsAccepted"])
        self.assertFalse(r["sameRunSmcReturnObserved"])
        self.assertFalse(r["guestSmcServiceImplementedOrSupported"])

    def test_unattested_entry_never_trusted(self):
        log=valid_log().replace("HXL1_COMPACT_ENTRY_OK","HXL1_COMPACT_ENTRY_OLD")
        r=m.analyze_log(log)
        self.assertFalse(r["smcCallArgumentsAccepted"])

    def test_wrong_entry_pointer_fails_closed(self):
        log=valid_log().replace("X0=0x48000000 X1=0x0","X0=0x48001000 X1=0x0")
        r=m.analyze_log(log)
        self.assertFalse(r["smcCallArgumentsAccepted"])

    def test_missing_smc_breakpoint_not_false_absence(self):
        log=valid_log().split("Breakpoint 2,")[0]+"GDB_BOUNDED_TIMEOUT\n"
        r=m.analyze_log(log)
        self.assertEqual(r["status"],"POST_ENTRY_SMC_NOT_REACHED_IN_BOUNDED_CAPTURE")
        self.assertFalse(r["smcCallArgumentsAccepted"])

    def test_wrong_stock_smc_opcode_not_accepted(self):
        log=valid_log().replace("0xd4000003","0xd503201f")
        r=m.analyze_log(log)
        self.assertEqual(r["status"],"LIVE_SMC_OPCODE_NOT_CORRELATED_TO_STOCK_IMAGE")

    def test_duplicate_smc_stop_fails(self):
        log=valid_log()+valid_log()[valid_log().index("HXL1_COMPACT_SMC_STOP"):]
        r=m.analyze_log(log)
        self.assertFalse(r["smcCallArgumentsAccepted"])

    def test_conditional_entry_before_smc_breakpoint(self):
        s=m.script(12351)
        self.assertIn("hbreak *0x40080000",s)
        self.assertIn("if $pc == 0x40080000 && $x0 == 0x48000000",s)
        self.assertIn("hbreak *0xffffff80080a5794",s)
        self.assertLess(s.index("hbreak *0x40080000"),s.index("hbreak *0xffffff80080a5794"))
        self.assertIn("x/1wx $pc",s)
        self.assertNotIn("set {",s)

    def test_timeout_is_bounded_and_no_guest_writes(self):
        code=Path(m.__file__).read_text()
        self.assertIn("timeout=timeout",code)
        self.assertIn("proc.terminate()",code)
        self.assertIn("proc.kill()",code)
        self.assertIn('"-nic","none"',code)
        for forbidden in ("adb shell","fastboot flash","memory_write(","set {"):
            self.assertNotIn(forbidden,code)

    def test_host_cli_runs_isolated(self):
        with tempfile.TemporaryDirectory() as temp:
            output=subprocess.run(
                [sys.executable,"-I",str(Path(m.__file__)),"--help"],
                cwd=temp,capture_output=True,text=True,timeout=10)
        self.assertEqual(output.returncode,0,output.stderr)
        self.assertIn("--preflight-only",output.stdout)
        self.assertIn("--output",output.stdout)

    def test_preflight_uses_compact_image_and_live_fdt_record(self):
        code=Path(m.__file__).read_text()
        self.assertIn("compact.verify_input",code)
        self.assertIn("compact.verify_capture",code)
        self.assertIn('saved.get("runtimeFdtSha256")',code)
        self.assertIn("EXPECTED_RUNTIME_BYTES=35168",code)

    def test_empty_log_does_not_prove_smc(self):
        result=m.analyze_log("")
        self.assertFalse(result["smcCallArgumentsAccepted"])
        self.assertFalse(result["vendorSmcServiceResultObserved"])

if __name__=="__main__":
    unittest.main()
