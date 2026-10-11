"""No-device guard tests for bounded stock-image QEMU GDB SMC register capture."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).with_name("run_y2q_hxl1_qemu_smc_register_capture.sh")

class SecureMonitorCaptureTests(unittest.TestCase):
    def test_bash_syntax(self):
        result=subprocess.run(["bash","-n",str(SCRIPT)],
                              capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
    def test_image_hash_gate_before_qemu_start(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            (root/"s20-artifacts").mkdir()
            (root/"s20-artifacts/kernel.bin").write_bytes(b"not genuine HXL1")
            env=os.environ.copy()
            env["HOME"]=str(root)
            result=subprocess.run(["bash",str(SCRIPT)],
                                  cwd=root,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertIn("SHA256 mismatch",result.stderr)
            self.assertFalse((root/"s20-artifacts/hxl1-research/qemu-smc-registers-20261011").exists())
    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            preexisting=root/"evidence"
            preexisting.mkdir()
            (preexisting/"source.log").write_text("keep")
            env=os.environ.copy()
            env["HOME"]=str(root)
            result=subprocess.run(["bash",str(SCRIPT),str(preexisting)],
                                  cwd=root,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn("Output exists",result.stderr)
            self.assertEqual((preexisting/"source.log").read_text(),"keep")
    def test_debugger_targets_verified_original_smc(self):
        content=SCRIPT.read_text()
        self.assertIn("SMC_PC=0xffffff80080a5794",content)
        self.assertIn("EXPECT_SHA=ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123",content)
        self.assertIn("hbreak *$SMC_PC",content)
        self.assertIn("if \\$pc == $SMC_PC",content)
        self.assertIn("X0=0x%lx X1=0x%lx",content)
    def test_runtime_bounded_and_no_device_contact(self):
        content=SCRIPT.read_text()
        self.assertIn("MAX_SECONDS=30",content)
        self.assertIn("timeout --signal=INT --kill-after=3s",content)
        self.assertIn('-S -gdb "tcp:127.0.0.1:$PORT"',content)
        self.assertIn('trap cleanup EXIT',content)
        for word in ("adb ","fastboot ","heimdall ","odin "):
            self.assertNotIn(word,content)

if __name__=="__main__":unittest.main()
