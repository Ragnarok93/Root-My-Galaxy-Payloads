"""Host-only original Image instruction-dependency tests for HXL1 compact QEMU."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_compact_fault_dependencies as a
from tools import y2q_hxl1_compact_exception_audit as prior

LOG=(
    "Taking exception 16 [Secure Monitor Call] on CPU 0\n"
    "...from EL1 to EL1\n"
    "...with ESR 0x0/0x02000000\n"
    "...with ELR 0xffffff80080a5794\n"
    "Taking exception 4 [Data Abort] on CPU 0\n"
    "...from EL1 to EL1\n"
    "...with ESR 0x25/0x96000005\n"
    "...with FAR 0x58\n"
    "...with ELR 0xffffff80082ac90c\n"
    "Taking exception 4 [Data Abort] on CPU 0\n"
    "...from EL1 to EL1\n"
    "...with ESR 0x25/0x96000005\n"
    "...with FAR 0x10\n"
    "...with ELR 0xffffff80086de39c\n"
).encode()

def synthetic_image():
    extent=a.EXPECTED_SITES[-1]-a.gate.VM_BASE+4
    out=bytearray(extent)
    for pc,word in a.secure.EXPECTED.items():
        off=pc-a.gate.VM_BASE
        out[off:off+4]=bytes.fromhex(word)[::-1]
    return bytes(out)

def linked():
    return {"compactInputSha256":a.COMPACT_INPUT_SHA,
            "runtimeGuestFdtBytes":a.SOURCE_GUEST_FDT_BYTES,
            "runtimeGuestFdtSha256":"known-guest-sha",
            "qmpStatus":"GUEST_PC_CHANGED_ACROSS_SNAPSHOTS",
            "qmpPcSequence":["0xffffff8008146ad4","0xffffff8008146ae4"],
            "exceptionFile":Path("/synthetic/exceptions.log")}

def symbols():
    return {"status":"RECOVERED_NM_SYMBOLS_UNVERIFIED",
            "sourceSha256":"synthetic",
            "entries":[(a.gate.VM_BASE,"T","source_test")]}

def material():
    image=synthetic_image()
    with patch.object(a.gate,"KERNEL_SHA",hashlib.sha256(image).hexdigest()):
        with patch.object(prior.shutil,"which",return_value=None):
            evidence=prior.extract_event_log(LOG)
            baseline=prior.source_correlate(evidence,image,symbols())
    baseline["verifiedEvidenceLinks"]={k:v for k,v in linked().items() if k!="exceptionFile"}
    return image,baseline

class CompactFaultDependencyTests(unittest.TestCase):
    def run_analysis(self,report=None,raw=LOG):
        image,baseline=material()
        with patch.object(a.gate,"KERNEL_SHA",hashlib.sha256(image).hexdigest()):
            return a.classify_prior(report or baseline,image,raw,linked())

    def test_exact_three_verified_source_opcodes(self):
        result=self.run_analysis()
        self.assertEqual([x["originalOpcode"] for x in result["events"]],
                         ["d4000003","f9402eb8","a9412149"])
        self.assertTrue(result["allThreeEventsCorrelatedToRawExceptionLog"])
        self.assertFalse(result["dataAbortCausedBySmcProven"])

    def test_smc_immediate_zero_not_guest_service_x0(self):
        smc=self.run_analysis()["events"][0]
        self.assertEqual(smc["instruction"]["instruction"],"SMC")
        self.assertEqual(smc["instruction"]["immediate"],0)
        self.assertFalse(smc["smcServiceReturnValueRead"])
        self.assertIn("UNVERIFIED",smc["status"])

    def test_ldr_x21_plus_0x58_is_zero_base_compatible_not_proven(self):
        e=self.run_analysis()["events"][1]
        self.assertEqual(e["instruction"]["instruction"],"LDR_X_UNSIGNED_OFFSET")
        self.assertEqual(e["baseRegister"],"x21")
        self.assertEqual(e["instruction"]["register"],"x24")
        self.assertEqual(e["candidateEffectiveOffsetsBytes"],[0x58])
        self.assertEqual(e["candidateBaseValuesIfAddressCalculationSimple"],["0x0"])
        self.assertTrue(e["zeroBaseConsistent"])
        self.assertFalse(e["nullBaseProven"])

    def test_ldp_x10_0x10_has_two_possible_faulting_words(self):
        e=self.run_analysis()["events"][2]
        self.assertEqual(e["instruction"]["instruction"],"LDP_X_OFFSET")
        self.assertEqual(e["instruction"]["registers"],["x9","x8"])
        self.assertEqual(e["baseRegister"],"x10")
        self.assertEqual(e["candidateEffectiveOffsetsBytes"],[0x10,0x18])
        self.assertEqual(e["candidateBaseValuesIfAddressCalculationSimple"],
                         ["0x0","0xfffffffffffffff8"])
        self.assertFalse(e["nullBaseProven"])

    def test_original_factory_sha_not_bypassed(self):
        image,baseline=material()
        with self.assertRaisesRegex(a.gate.GateError,"SHA256 mismatch"):
            a.classify_prior(baseline,image,LOG,linked())

    def test_mutated_report_opcode_rejected(self):
        _,report=material()
        report["events"][1]["originalSource"]["originalOpcode"]="00000000"
        with self.assertRaisesRegex(a.FaultDependencyError,"instruction bytes"):
            self.run_analysis(report)

    def test_mutated_report_far_rejected(self):
        _,report=material()
        report["events"][1]["far"]="0x60"
        with self.assertRaisesRegex(a.FaultDependencyError,"differs from raw"):
            self.run_analysis(report)

    def test_raw_log_tamper_fails_sha_provenance(self):
        with self.assertRaisesRegex(a.FaultDependencyError,"hash/event count"):
            self.run_analysis(raw=LOG+b"extra")

    def test_duplicate_exception_address_rejected(self):
        _,report=material()
        report["events"][2]["elr"]=report["events"][1]["elr"]
        with self.assertRaisesRegex(a.FaultDependencyError,"uniquely"):
            self.run_analysis(report)

    def test_missing_compact_guest_linkage_rejected(self):
        _,report=material()
        report["verifiedEvidenceLinks"]["runtimeGuestFdtBytes"]=2117184
        with self.assertRaisesRegex(a.FaultDependencyError,"runtime evidence"):
            self.run_analysis(report)

    def test_causation_not_inferred_from_event_order(self):
        result=self.run_analysis()
        self.assertFalse(result["sameRunSmcReturnCaptured"])
        self.assertFalse(result["dataAbortBaseRegistersCaptured"])
        self.assertFalse(result["secureMonitorFunctional"])
        self.assertFalse(result["linuxMemblockReservationVerified"])
        self.assertFalse(result["secureRkpPoolReserved"])

    def test_no_emulator_or_physical_device_operations(self):
        s=Path(a.__file__).read_text()
        for forbidden in ("fastboot flash","adb shell","qemu-system-aarch64",
                          "cpu_physical_memory_write","memory_write("):
            self.assertNotIn(forbidden,s)
        self.assertIn("compact.verify_linked_evidence",s)
        self.assertIn("gate.valid_source(image)",s)

    def test_help_without_repo_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            process=subprocess.run(
                [sys.executable,"-I",str(Path(a.__file__)),"--help"],
                cwd=temp,capture_output=True,text=True,timeout=10)
        self.assertEqual(process.returncode,0,process.stderr)
        self.assertIn("--input",process.stdout)

if __name__=="__main__":
    unittest.main()
