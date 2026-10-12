"""Host-only QEMU exception evidence tests for compact HXL1 boot."""
from __future__ import annotations
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_compact_exception_audit as a

TRACE=(
    "Taking exception 16 [Secure Monitor Call] on CPU 0\n"
    "...from EL1 to EL1\n"
    "...with ESR 0x0/0x2000000\n"
    "...with ELR 0xffffff80080a5794\n"
    "...to EL1 PC 0xffffff8008082200 PSTATE 0x3c5\n"
    "Taking exception 4 [Data Abort] on CPU 0\n"
    "...from EL1 to EL1\n"
    "...with ESR 0x25/0x96000005\n"
    "...with FAR 0x58\n"
    "...with ELR 0xffffff80082ac90c\n"
    "...to EL1 PC 0xffffff8008082200 PSTATE 0x3c5\n"
    "Taking exception 4 [Data Abort] on CPU 0\n"
    "...from EL1 to EL1\n"
    "...with ESR 0x25/0x96000005\n"
    "...with FAR 0x10\n"
    "...with ELR 0xffffff80086de39c\n"
    "...to EL1 PC 0xffffff8008082200 PSTATE 0x3c5\n"
).encode()

def image():
    length=(a.KNOWN_FAULTS[-1]-a.gate.VM_BASE)+64
    return bytes(length) # zero words synthetic, not actual original data

def recovered_symbols():
    return {"status":"RECOVERED_NM_SYMBOLS_UNVERIFIED",
            "sourceSha256":"mock",
            "entries":[(a.SMC_PC-0x20,"T","smc_candidate"),
                       (a.KNOWN_FAULTS[0]-0x10,"T","memblock_reserve"),
                       (a.KNOWN_FAULTS[1]-0x10,"T","fault_func")]}

class CompactExceptionAuditTests(unittest.TestCase):
    def test_smc_and_two_data_aborts_recognized(self):
        r=a.extract_event_log(TRACE)
        self.assertEqual(r["totalExceptionMarkers"],3)
        self.assertEqual([x["elr"] for x in r["events"]],
                         [hex(a.SMC_PC),hex(a.KNOWN_FAULTS[0]),hex(a.KNOWN_FAULTS[1])])

    def test_far_addresses_preserved_not_interpreted_as_full_pointers(self):
        r=a.extract_event_log(TRACE)
        self.assertEqual([x["far"] for x in r["events"]], [None,"0x58","0x10"])
        self.assertEqual(r["events"][1]["esrDecoded"]["category"],
                         "DATA_ABORT_CURRENT_EL")

    def test_abort_esr_reports_translation_failure_and_read(self):
        r=a.extract_event_log(TRACE)
        for e in r["events"][1:]:
            self.assertEqual(e["esrDecoded"]["memoryAccess"],"read")
            self.assertEqual(e["esrDecoded"]["faultClass"],
                             "TRANSLATION_FAULT_LEVEL_1")

    def test_source_correlation_never_claims_real_monitor_or_memblock(self):
        raw=image()
        original=a.extract_event_log(TRACE)
        with patch.object(a.gate,"KERNEL_SHA",hashlib.sha256(raw).hexdigest()):
            with patch.object(a.shutil,"which",return_value=None):
                r=a.source_correlate(original,raw,recovered_symbols())
        self.assertEqual(r["status"],"ORIGINAL_IMAGE_CORRELATED_COMPACT_QEMU_EXCEPTIONS")
        self.assertTrue(r["knownSmcSitePresentInRetainedEvents"])
        self.assertEqual(r["knownFaultSitesPresentInRetainedEvents"],
                         [hex(x) for x in a.KNOWN_FAULTS])
        self.assertFalse(r["guestSmcFunctionalityVerified"])
        self.assertFalse(r["guestLinuxMemblockAllocatorStateVerified"])
        self.assertFalse(r["linuxUserspaceBootVerified"])
        self.assertFalse(r["rkpProtectedPoolReserved"])
        self.assertFalse(r["events"][0]["executedGuestInstructionBytesIndependentlyRead"])

    def test_bad_factory_sha_fails_closed(self):
        with self.assertRaisesRegex(a.gate.GateError,"SHA256 mismatch"):
            a.source_correlate(a.extract_event_log(TRACE),image(),recovered_symbols())

    def test_exception_event_retention_is_bounded(self):
        r=a.extract_event_log(TRACE*20,limit=4)
        self.assertEqual(r["totalExceptionMarkers"],60)
        self.assertEqual(r["retainedEventCount"],4)
        self.assertTrue(r["samplesTruncatedToLimit"])

    def test_untrusted_log_exceeding_limit_refused(self):
        with self.assertRaisesRegex(a.CompactExceptionError,"exceeds 16MiB"):
            a.extract_event_log(b"\0"*(a.MAX_LOG+1))

    def test_no_events_returns_empty_not_smc_success(self):
        r=a.extract_event_log(b"Invalid read at addr 0x3FFFFFFC\n")
        self.assertEqual(r["totalExceptionMarkers"],0)
        self.assertEqual(r["events"],[])

    def test_log_hash_is_exact(self):
        r=a.extract_event_log(TRACE)
        self.assertEqual(r["logSha256"],hashlib.sha256(TRACE).hexdigest())

    def test_source_uses_only_offline_existing_artifacts(self):
        s=Path(a.__file__).read_text()
        for forbidden in ("qemu-system-aarch64","fastboot flash",
                          "adb shell","memory_write(", "cpu_physical_memory_write"):
            self.assertNotIn(forbidden,s)
        self.assertIn("compact_capture.verify_capture",s)
        self.assertIn("recovery.verify_recovery",s)
        self.assertIn("gate.valid_source(image)",s)

    def test_cli_isolated_help(self):
        with tempfile.TemporaryDirectory() as root:
            res=subprocess.run([sys.executable,"-I",str(Path(a.__file__)),"--help"],
                cwd=root,capture_output=True,text=True,timeout=10)
        self.assertEqual(res.returncode,0,res.stderr)
        self.assertIn("--research-root",res.stdout)

    def test_qmp_input_origin_has_separate_compact_sha(self):
        s=Path(a.__file__).read_text()
        self.assertIn('qmp.get("mode")!="compact-canary"',s)
        self.assertIn('qmp.get("inputDtbSha256")!=checked["overrideSha256"]',s)
        self.assertIn('recorded.get("compactOverrideSha256")',s)

if __name__=="__main__":
    unittest.main()
