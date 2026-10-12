"""Host-only original compact SMC source/ABI attestation regressions."""
from __future__ import annotations
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_compact_bitmap_call_audit as t
from tools import y2q_hxl1_qemu_compact_smc_registers as smc
from tools.test_y2q_hxl1_rkp_bitmap_abi_audit import UH, RKP

GDB=(
    "Breakpoint 1, 0x40080000 in ?? ()\n"
    "HXL1_COMPACT_ENTRY_OK PC=0x40080000 X0=0x48000000 X1=0x0 X2=0x0 X3=0x0\n"
    "Breakpoint 2, 0xffffff80080a5794 in ?? ()\n"
    "HXL1_COMPACT_SMC_STOP PC=0xffffff80080a5794 X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000 X4=0x0 X5=0x0 X6=0x3f\n"
    "0xffffff80080a5794:\t0xd4000003\n"
)
def report():
    return {
        **smc.analyze_log(GDB),
        "status":"STOCK_SMC_0_LIVE_ARGUMENTS_CAPTURED",
        "originalFactoryImageSha256":t.gate.KERNEL_SHA,
        "sourceCompactOverrideSha256":smc.EXPECTED_INPUT_SHA,
        "originalGuestFdtProofBytes":smc.EXPECTED_RUNTIME_BYTES,
        "gdbExitCode":0,
    }

class CompactBitmapSourceAbiTests(unittest.TestCase):
    def evaluate(self,rep=None,log=GDB,uh=UH,rkp=RKP,nm_text=None):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"stock.nm"
            path.write_text(nm_text if nm_text is not None else
                "ffffff800a4dd0b8 B rkp_s_bitmap_buffer\n")
            return t.evaluate(rep or report(),log,uh,rkp,path,
                              {"uh.h":"fixture-sha","rkp.h":"fixture-sha"})

    def test_compact_smc_is_original_rkp_bitmap_request(self):
        r=self.evaluate()
        self.assertEqual(r["sourceCommand"],"RKP_GET_RKP_GET_BUFFER_BITMAP")
        self.assertEqual(r["sourceAppId"],"0xc300c002")
        self.assertEqual(r["sourceCommandValue"],"0x15")
        self.assertEqual(r["status"],"COMPACT_GUEST_RKP_BITMAP_SOURCE_ABI_CORROBORATED")
        self.assertEqual(r["x2RecoveredBitmapSlot"]["status"],
                         "RECOVERED_SYMBOL_ADDRESS_CORRELATES")
        self.assertFalse(r["rkpBitmapPointerWrittenBySecureMonitor"])

    def test_x6_is_observed_but_not_explicit_uh_call_argument(self):
        r=self.evaluate()
        self.assertEqual(r["x6ObservedButNotSourceDefinedArgument"],"0x3f")
        self.assertFalse(r["x6ExplicitSourceParameter"])

    def test_non_samsung_source_app_rejected(self):
        with self.assertRaisesRegex(t.BitmapEvidenceError,"source meaning"):
            self.evaluate(uh=UH.replace("APP_RKP 2","APP_RKP 3"))

    def test_wrong_command_source_rejected(self):
        with self.assertRaisesRegex(t.BitmapEvidenceError,"source meaning"):
            self.evaluate(rkp=RKP.replace("= 0x15","= 0x14"))

    def test_source_pointer_argument_order_rejected(self):
        with self.assertRaisesRegex(t.BitmapEvidenceError,"source meaning"):
            self.evaluate(rkp=RKP.replace("(u64)&rkp_s_bitmap_buffer, (u64)memstart_addr",
                                          "(u64)memstart_addr, (u64)&rkp_s_bitmap_buffer"))

    def test_recovered_bitmap_pointer_differs_rejected(self):
        with self.assertRaisesRegex(t.BitmapEvidenceError,"X2 did not correlate"):
            self.evaluate(nm_text="ffffff800a4dd0b0 B rkp_s_bitmap_buffer\n")

    def test_smc_report_register_tampering_rejected(self):
        r=report()
        r["registerArguments"]["X3"]="0x40001000"
        with self.assertRaisesRegex(t.BitmapEvidenceError,"independently match"):
            self.evaluate(rep=r)

    def test_smc_log_opcode_tampering_rejected(self):
        with self.assertRaisesRegex(t.BitmapEvidenceError,"independently match"):
            self.evaluate(log=GDB.replace("0xd4000003","0xd503201f"))

    def test_report_original_fdt_bytes_not_pinned_rejected(self):
        r=report()
        r["originalGuestFdtProofBytes"]=2117184
        with self.assertRaisesRegex(t.BitmapEvidenceError,"independently match"):
            self.evaluate(rep=r)

    def test_nonzero_gdb_status_rejected(self):
        r=report()
        r["gdbExitCode"]=124
        with self.assertRaisesRegex(t.BitmapEvidenceError,"independently match"):
            self.evaluate(rep=r)

    def test_no_root_or_uh_emulator_proof(self):
        r=self.evaluate()
        self.assertFalse(r["sourceFaithfulQemuSecureMonitorImplemented"])
        self.assertFalse(r["guestProtectedPoolReserved"])
        self.assertFalse(r["hardwareBootloaderUnlocked"])
        self.assertFalse(r["kernelSuDeployed"])

    def test_direct_invocation_help_isolated(self):
        with tempfile.TemporaryDirectory() as folder:
            res=subprocess.run([sys.executable,"-I",str(Path(t.__file__)),"--help"],
                               cwd=folder,text=True,capture_output=True,timeout=10)
        self.assertEqual(res.returncode,0,res.stderr)
        self.assertIn("--source-root",res.stdout)

    def test_offline_no_qemu_or_phone_calls(self):
        text=Path(t.__file__).read_text()
        for bad in ("qemu-system-aarch64","fastboot flash","adb shell",
                    "cpu_physical_memory_write"):
            self.assertNotIn(bad,text)
        self.assertIn("smc.verify_preflight",text)

if __name__=="__main__":
    unittest.main()
