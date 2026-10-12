"""Synthetic host-only tests for HXL1 registered producer paths and source branches."""
from __future__ import annotations
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_compact_regorigin_route_audit as a
from tools import y2q_hxl1_qemu_compact_register_provenance as owner
from tools.test_y2q_hxl1_qemu_compact_register_provenance import (
    log_for,original_synthetic_bytes,
)

COMPACT="1530da694b887fbe9918aa922eeafcdaa3ef0c900e6eae279402464b46b83fdd"

def report(target,raw):
    r=owner.analyze(raw,target)
    r.update(gdbExitCode=0,targetDevice="SM-G986U1/G986U1UESCHXL1",
             stockKernelSha256=a.gate.KERNEL_SHA,
             compactDtbSha256=COMPACT,
             earlierVerifiedRuntimeFdtBytes=a.smc.EXPECTED_RUNTIME_BYTES)
    return r

def with_source_read(raw,target="x10",base=0xffffff800ac2f9c0,
                     read=0,correct=True):
    if target=="x21":
        effective=base+72
    else:
        effective=base+2840
    if not correct:effective+=16
    source=(f"HXL1_PRODUCER_SOURCE_ADDRESS {hex(effective)}\n"
            f"{hex(effective)}:\t0x{read:016x}\n")
    return raw.replace("HXL1_REG_FAULT",source+"HXL1_REG_FAULT")

class RouteAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock=original_synthetic_bytes()

    def review(self,target,raw,rep=None):
        with patch.object(a.gate,"valid_source",return_value=None):
            return a.cross_check_saved(target,raw,rep or report(target,raw),
                                       self.stock,COMPACT)

    def test_owner_x21_skipped_stack_restore_means_unknown_source(self):
        raw=log_for("x21",producer=False,fault=True)
        result=self.review("x21",raw)
        self.assertTrue(result["faultObserved"])
        self.assertFalse(result["producerObserved"])
        self.assertFalse(result["candidateProducerExecutedBeforeFault"])
        self.assertFalse(result["producerSourceMemoryReadAttested"])
        self.assertIn("not hit",result["reasonIfProducerNotObserved"])

    def test_x10_same_run_memory_read_at_exact_source_matches_zero_base(self):
        base=0xffffff800ac2f9c0
        raw=with_source_read(log_for("x10",source_base=base,base=0),base=base)
        result=self.review("x10",raw)
        self.assertTrue(result["producerObserved"])
        self.assertEqual(result["producerSourceMemoryValue"],"0x0")
        self.assertTrue(result["sourceReadAndFaultBaseEqual"])
        self.assertTrue(result["x10SourceFieldValueEstablished"])
        self.assertFalse(result["oneStepRegisterDefUseProven"])

    def test_x10_read_absent_is_unknown_not_zero(self):
        raw=log_for("x10",source_base=0xffffff800ac2f9c0)
        res=self.review("x10",raw)
        self.assertFalse(res["x10SourceFieldValueEstablished"])
        self.assertIsNone(res["producerSourceMemoryValue"])
        self.assertFalse(res["sourceReadAndFaultBaseEqual"])

    def test_x10_field_address_mismatch_never_claims_read(self):
        base=0xffffff800ac2f9c0
        raw=with_source_read(log_for("x10",source_base=base),base=base,correct=False)
        res=self.review("x10",raw)
        self.assertFalse(res["sourceReadAndFaultBaseEqual"])
        self.assertFalse(res["producerSourceMemoryReadAttested"])

    def test_x10_memory_nonzero_not_reconciled_to_zero_register(self):
        base=0xffffff800ac2f9c0
        raw=with_source_read(log_for("x10",source_base=base),base=base,read=0x1234)
        res=self.review("x10",raw)
        self.assertEqual(res["producerSourceMemoryValue"],"0x1234")
        self.assertFalse(res["sourceReadAndFaultBaseEqual"])

    def test_gdb_report_tamper_refused(self):
        raw=log_for("x21",producer=False)
        rep=report("x21",raw)
        rep["faultBaseValueBefore"]="0x1"
        with self.assertRaisesRegex(a.RouteEvidenceError,"raw GDB"):
            self.review("x21",raw,rep)

    def test_wrong_compact_input_sha_rejected(self):
        raw=log_for("x21",producer=False)
        with self.assertRaisesRegex(a.RouteEvidenceError,"provenance"):
            with patch.object(a.gate,"valid_source",return_value=None):
                a.cross_check_saved("x21",raw,report("x21",raw),self.stock,"bad")

    def test_nonzero_gdb_exit_rejected(self):
        raw=log_for("x21",producer=False)
        rep=report("x21",raw)
        rep["gdbExitCode"]=124
        with self.assertRaisesRegex(a.RouteEvidenceError,"provenance"):
            self.review("x21",raw,rep)

    def test_no_live_fault_rejected(self):
        raw=log_for("x10",fault=False)
        with self.assertRaisesRegex(a.RouteEvidenceError,"No same-session"):
            self.review("x10",raw)

    def test_b_and_bl_pc_relative(self):
        pc=0xffffff80082ac900
        self.assertEqual(a.decode_direct_branch(pc,0x14000002)["target"],hex(pc+8))
        self.assertEqual(a.decode_direct_branch(pc,0x94000002)["branchKind"],"BL")
        self.assertEqual(a.decode_direct_branch(pc,0x17ffffff)["target"],hex(pc-4))

    def test_conditional_and_cbz_branch(self):
        pc=0xffffff80082ac900
        self.assertEqual(a.decode_direct_branch(pc,0x54000040)["target"],hex(pc+8))
        self.assertEqual(a.decode_direct_branch(pc,0xb4000040)["branchKind"],"CBZ")
        self.assertEqual(a.decode_direct_branch(pc,0xb5000040)["branchKind"],"CBNZ")

    def test_tbz_tbnz_branch(self):
        pc=0xffffff80082ac900
        self.assertEqual(a.decode_direct_branch(pc,0x36000040)["target"],hex(pc+8))
        self.assertEqual(a.decode_direct_branch(pc,0x37000040)["branchKind"],"TBNZ")

    def test_register_indirect_branch_not_guessed(self):
        self.assertIsNone(a.decode_direct_branch(0x40080000,0xd61f0020)) # BR x1
        self.assertIsNone(a.decode_direct_branch(0x40080000,0xd65f03c0)) # RET

    def test_source_direct_edge_to_fault_not_executed(self):
        image=bytearray(self.stock)
        fault=owner.CANDIDATES["x21"]["fault"]
        branch=fault-0x14
        displacement=(fault-branch)//4
        off=branch-a.gate.VM_BASE
        image[off:off+4]=(0x14000000|displacement).to_bytes(4,"little")
        r=a.branch_neighborhood(bytes(image),fault)
        self.assertTrue(any(e["source"]==hex(branch) and e["target"]==hex(fault)
                            for e in r["candidateIncomingDirectEdgesNearFault"]))
        self.assertFalse(r["candidateIncomingDirectEdgesNearFault"][0]["branchExecutedInGuest"])
        self.assertTrue(r["indirectBranchesAndExceptionReturnsNotEnumerated"])

    def test_window_alignment_and_bounds_fail_closed(self):
        with self.assertRaisesRegex(a.RouteEvidenceError,"alignment"):
            a.branch_neighborhood(self.stock,owner.CANDIDATES["x21"]["fault"],back=0x813)
        with self.assertRaisesRegex(a.RouteEvidenceError,"outside"):
            a.branch_neighborhood(self.stock,a.gate.VM_BASE+4)

    def test_isolated_help(self):
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([sys.executable,"-I",str(Path(a.__file__)),"--help"],
                             cwd=d,capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("--research-root",r.stdout)

    def test_no_emulator_or_phone_access(self):
        source=Path(a.__file__).read_text()
        for token in ("qemu-system-aarch64","fastboot flash","adb shell",
                      "cpu_physical_memory_write","memory_write("):
            self.assertNotIn(token,source)
        self.assertIn("owner.analyze(raw,target)",source)
        self.assertIn("smc.verify_preflight",source)

if __name__=="__main__":
    unittest.main()
