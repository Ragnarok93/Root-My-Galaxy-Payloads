"""Synthetic, host-only cross-run compact HXL1 fault-register attribution."""
from __future__ import annotations
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_compact_fault_live_attribution as audit
from tools import y2q_hxl1_qemu_compact_fault_regs as regs
from tools.test_y2q_hxl1_qemu_compact_fault_regs import sample


def image():
    top=max(t[0] for t in regs.TARGETS.values())-audit.gate.VM_BASE
    b=bytearray(top+256)
    for pc,opcode,_ in regs.TARGETS.values():
        off=pc-audit.gate.VM_BASE
        b[off:off+4]=int(opcode,16).to_bytes(4,"little")
    return bytes(b)

def deps():
    return {
        "status":"FACTORY_INSTRUCTION_DEPENDENCIES_OFFLINE_VERIFIED",
        "originalFactoryImageSha256":audit.gate.KERNEL_SHA,
        "sourceCompactRuntimeFdtBytes":audit.smc.EXPECTED_RUNTIME_BYTES,
        "sourceCompactOverrideSha256":audit.smc.EXPECTED_INPUT_SHA,
        "allThreeEventsCorrelatedToRawExceptionLog":True,
        "events":[
            {"elr":hex(pc),"originalOpcode":opcode,
             "far":hex(far),"baseRegister":target,
             "esr":"0x96000005"}
            for target,(pc,opcode,far) in regs.TARGETS.items()],
    }

def original_report(target="x21",base=0):
    rep=regs.analyze_log(sample(target,base=base),target)
    rep.update(
        originalImageSha256=audit.gate.KERNEL_SHA,
        compactSourceSha256=audit.smc.EXPECTED_INPUT_SHA,
        earlierVerifiedGuestFdtSizeBytes=audit.smc.EXPECTED_RUNTIME_BYTES,
        gdbExitCode=0,targetDevice="SM-G986U1/G986U1UESCHXL1")
    return rep

def symbols():
    return {"status":"RECOVERED_NM_SYMBOLS_UNVERIFIED",
            "entries":[(audit.gate.VM_BASE,"T","synthetic_head"),
                       (regs.TARGETS["x21"][0]-0x20,"T","candidate_x21"),
                       (regs.TARGETS["x10"][0]-0x20,"T","candidate_x10")]}

class LiveFaultAttributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=image()

    def correlate(self,target="x21",base=0,data=None,log=None,dep=None):
        source=log if log is not None else sample(target,base=base)
        saved=data if data is not None else original_report(target,base=base)
        prior=dep if dep is not None else deps()
        with patch.object(audit.gate,"valid_source",return_value=None), \
             patch.object(audit.shutil,"which",return_value=None):
            return audit.correlate(saved,source,self.image,prior,symbols(),target)

    def test_original_x21_zero_at_live_opcode(self):
        out=self.correlate()
        self.assertTrue(out["nullBaseConfirmedAtPreLoadBreakpoint"])
        self.assertEqual(out["liveBaseRegisterValue"],"0x0")
        self.assertEqual(out["originalInstructionAddress"],"0xffffff80082ac90c")
        self.assertEqual(out["factoryOpcode"],"f9402eb8")
        self.assertEqual(out["liveExpectedEffectiveAddresses"],["0x58"])
        self.assertTrue(out["priorGuestFarMatchesOneCandidateAccess"])

    def test_smc_plus_four_missing_never_says_service_failed(self):
        out=self.correlate(log=sample("x21",ret=False),
                           data=original_report_no_return())
        self.assertFalse(out["sameRunSmcPostInstructionPcObserved"])
        self.assertFalse(out["realUhRkpServiceSupported"])
        self.assertFalse(out["smcCausedNullBaseOrAbortProven"])
        self.assertFalse(out["sameRunAbortAfterBreakpointCaptured"])

    def test_x10_pair_offset_is_two_candidates(self):
        result=self.correlate("x10")
        self.assertEqual(result["liveExpectedEffectiveAddresses"],["0x10","0x18"])
        self.assertEqual(result["nearestRecoveredInstructionSymbol"]["name"],
                         "candidate_x10")
        self.assertTrue(result["nullBaseConfirmedAtPreLoadBreakpoint"])

    def test_nonzero_x21_base_never_claims_null(self):
        result=self.correlate(base=0x40000000)
        self.assertFalse(result["nullBaseConfirmedAtPreLoadBreakpoint"])
        self.assertFalse(result["priorGuestFarMatchesOneCandidateAccess"])
        self.assertEqual(result["liveExpectedEffectiveAddresses"],["0x40000058"])

    def test_wrong_factory_opcode_refused(self):
        changed=bytearray(self.image)
        off=regs.TARGETS["x21"][0]-audit.gate.VM_BASE
        changed[off:off+4]=b"\x00"*4
        with patch.object(audit.gate,"valid_source",return_value=None):
            with self.assertRaisesRegex(audit.AttributionError,"factory"):
                audit.correlate(original_report(),sample(),bytes(changed),
                                deps(),symbols(),"x21")

    def test_tampered_report_register_rejected_against_original_gdb(self):
        bad=original_report()
        bad["preFaultBaseRegisterValue"]="0xfeed"
        with self.assertRaisesRegex(audit.AttributionError,"differs from original GDB"):
            self.correlate(data=bad)

    def test_wrong_guest_image_hash_rejected(self):
        bad=original_report()
        bad["originalImageSha256"]="0"*64
        with self.assertRaisesRegex(audit.AttributionError,"pinned original"):
            self.correlate(data=bad)

    def test_nonzero_gdb_exit_rejected(self):
        bad=original_report()
        bad["gdbExitCode"]=124
        with self.assertRaisesRegex(audit.AttributionError,"pinned original"):
            self.correlate(data=bad)

    def test_prior_far_mismatch_not_attributed(self):
        bad=deps()
        bad["events"][0]["far"]="0x60"
        with self.assertRaisesRegex(audit.AttributionError,"opcode/FAR/base"):
            self.correlate(dep=bad)

    def test_prior_event_missing_fails(self):
        bad=deps()
        bad["events"]=[]
        with self.assertRaisesRegex(audit.AttributionError,"missing/ambiguous"):
            self.correlate(dep=bad)

    def test_prior_fdt_size_mismatch_fails(self):
        bad=deps()
        bad["sourceCompactRuntimeFdtBytes"]=2117184
        with self.assertRaisesRegex(audit.AttributionError,"prior QEMU"):
            self.correlate(dep=bad)

    def test_missing_smc_stage_in_live_gdb_cannot_attribute(self):
        with self.assertRaisesRegex(audit.AttributionError,"actual GDB"):
            self.correlate(log=sample().replace("HXL1_SMC_PRE","HXL1_SMC_MISSING"))

    def test_x21_original_source_symbol_reconstruction_not_proof_of_function(self):
        result=self.correlate()
        self.assertIn("UNVERIFIED",result["nearestRecoveredInstructionSymbol"]["status"])
        self.assertEqual(result["nearestRecoveredInstructionSymbol"]["name"],
                         "candidate_x21")
        self.assertFalse(result["smcCausedNullBaseOrAbortProven"])

    def test_cli_runs_isolated(self):
        with tempfile.TemporaryDirectory() as d:
            result=subprocess.run([sys.executable,"-I",str(Path(audit.__file__)),"--help"],
                                  cwd=d,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("--target",result.stdout)

    def test_no_qemu_or_physical_device_actions(self):
        s=Path(audit.__file__).read_text()
        for forbidden in ("qemu-system-aarch64","adb shell","fastboot flash",
                          "cpu_physical_memory_write"):
            self.assertNotIn(forbidden,s)
        self.assertIn("regs.analyze_log",s)
        self.assertIn("sites.window",s)

def original_report_no_return():
    r=regs.analyze_log(sample("x21",ret=False),"x21")
    r.update(originalImageSha256=audit.gate.KERNEL_SHA,
             compactSourceSha256=audit.smc.EXPECTED_INPUT_SHA,
             earlierVerifiedGuestFdtSizeBytes=audit.smc.EXPECTED_RUNTIME_BYTES,
             gdbExitCode=0,targetDevice="SM-G986U1/G986U1UESCHXL1")
    return r

if __name__=="__main__":
    unittest.main()
