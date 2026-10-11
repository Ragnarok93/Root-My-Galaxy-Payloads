"""Bounded Samsung HXL1 SMC and near-null Data Abort factory-opcode tests."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_qemu_secure_monitor_gate as t

def pinned_image_fixture():
    raw=bytearray(0x65e3a0 + 8)
    for va, op in t.EXPECTED.items():
        off=va-t.faults.VM_BASE
        raw[off:off+4]=int(op,16).to_bytes(4,"little")
    return bytes(raw)

def report_fixture():
    return {
        "target":t.faults.TARGET,
        "originalKernelImageSha256":t.trace.KERNEL_HASH,
        "factoryImageTranslationCorrelated":True,
        "virtualBase":hex(t.faults.VM_BASE),
        "exceptions":[{
            "elr":va,
            "far":{0xffffff80080a5794:None,0xffffff80082ac90c:0x58,
                   0xffffff80086de39c:0x10}[va],
            "originalImage":{"originalOpcode":op},
            "qemuDescription":"fixture only",
        } for va,op in t.EXPECTED.items()]
    }

class SecureMonitorGateTests(unittest.TestCase):
    def test_smc_zero_is_not_brk_or_hvc(self):
        self.assertEqual(t.decode(0xd4000003)["instruction"],"SMC")
        self.assertEqual(t.decode(0xd4000003)["immediate"],0)
        self.assertNotEqual(t.decode(0xd4000002)["instruction"],"SMC")
        self.assertNotEqual(t.decode(0xd4200000)["instruction"],"SMC")
    def test_smc_immediate_is_not_app_id(self):
        self.assertEqual(t.decode(0xd4000023)["immediate"],1)
        self.assertEqual(t.decode(0xd4000023)["x0CallId"],"UNOBSERVED")
    def test_ldr_offset_and_register(self):
        d=t.decode(0xf9402eb8)
        self.assertEqual(d["instruction"],"LDR_X_UNSIGNED_OFFSET")
        self.assertEqual(d["register"],"x24")
        self.assertEqual(d["baseRegister"],"x21")
        self.assertEqual(d["byteOffset"],0x58)
    def test_ldp_pair_offset_and_registers(self):
        d=t.decode(0xa9412149)
        self.assertEqual(d["instruction"],"LDP_X_OFFSET")
        self.assertEqual(d["registers"],["x9","x8"])
        self.assertEqual(d["baseRegister"],"x10")
        self.assertEqual(d["byteOffset"],0x10)
    def test_signed_pair_imm_is_sign_extended(self):
        d=t.decode(0xa97f2149)
        self.assertEqual(d["byteOffset"],-0x10)
    def test_three_original_faults_in_source_order(self):
        out=t.analyze(report_fixture(),pinned_image_fixture())
        self.assertEqual(len(out["faults"]),3)
        self.assertEqual([e["decoded"]["instruction"] for e in out["faults"]],
                         ["SMC","LDR_X_UNSIGNED_OFFSET","LDP_X_OFFSET"])
        self.assertEqual([e.get("candidateBaseRegisterValue") for e in out["faults"]],
                         [None,"0x0","0x0"])
        self.assertTrue(out["forkRelevantButNotReady"])
        self.assertFalse(out["smcRegisterArgumentsAvailable"])
        self.assertFalse(out["guestSuccessfullyBooted"])
    def test_fork_smc_ids_are_not_pretended_to_be_captured(self):
        out=t.analyze(report_fixture(),pinned_image_fixture())
        a=out["faults"][0]
        self.assertEqual(a["decoded"]["x0CallId"],"UNOBSERVED")
        self.assertEqual(a["forkCallIdCompatible"],"UNDETERMINED_UNTIL_GUEST_X0_CAPTURED")
        self.assertIn("0xc300c001",a["forkRecognizedCallIds"])
        self.assertIn("0xc300c002",a["forkRecognizedCallIds"])
    def test_mismatched_original_opcode_stops(self):
        bad=bytearray(pinned_image_fixture())
        bad[0x25794]=0
        with self.assertRaisesRegex(t.GateError,"opcode mismatch"):
            t.analyze(report_fixture(),bytes(bad))
    def test_report_opcode_tamper_stops(self):
        wrong=report_fixture()
        wrong["exceptions"][0]["originalImage"]["originalOpcode"]="d4200000"
        with self.assertRaisesRegex(t.GateError,"opcode mismatch"):
            t.analyze(wrong,pinned_image_fixture())
    def test_missing_or_duplicated_exception_rejected(self):
        wrong=report_fixture()
        wrong["exceptions"]=wrong["exceptions"][:2]
        with self.assertRaisesRegex(t.GateError,"exactly three"):
            t.analyze(wrong,pinned_image_fixture())
    def test_non_hxl1_report_rejected(self):
        wrong=report_fixture()
        wrong["target"]="WRONG"
        with self.assertRaisesRegex(t.GateError,"not HXL1"):
            t.analyze(wrong,pinned_image_fixture())
    def test_direct_script_entrypoint_outside_checkout(self):
        script=Path(t.__file__).resolve()
        with tempfile.TemporaryDirectory() as d:
            result=subprocess.run([sys.executable,"-I",str(script),"--help"],
                                  cwd=d,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("--fault-sites",result.stdout)
    def test_no_device_or_guest_actions(self):
        self.assertIn("never launches QEMU",t.__doc__)
        self.assertFalse(hasattr(t,"boot"))
        self.assertFalse(hasattr(t,"flash"))

if __name__=="__main__":
    unittest.main()
