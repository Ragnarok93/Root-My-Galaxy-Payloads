"""Host-only original HXL1 slab/panic window and config-source regressions."""
from __future__ import annotations
import gzip
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_compact_fault_function_windows as w
from tools import y2q_hxl1_qemu_compact_fault_regs as regs

PC21=regs.TARGETS["x21"][0]
PC10=regs.TARGETS["x10"][0]

def symbols():
    return {"status":"RECOVERED_NM_SYMBOLS_UNVERIFIED",
            "sourceSha256":"synthetic",
            "entries":[
                (w.gate.VM_BASE,"T","_text"),
                (PC21-0x310,"T","kmem_cache_alloc"),
                (PC10-0x124,"T","dump_stack_minidump"),
            ]}

def old_result(target:str):
    pc,op,far=regs.TARGETS[target]
    return {"status":"ORIGINAL_COMPACT_FAULT_BASE_AT_SOURCE_INSTRUCTION_VERIFIED",
            "baseRegister":target.upper(),
            "liveBaseRegisterValue":"0x0",
            "originalImageSha256":w.gate.KERNEL_SHA,
            "originalInstructionAddress":hex(pc),
            "separatePriorGuestDataAbortFar":hex(far),
            "smcCausedNullBaseOrAbortProven":False,
            "liveLinkRegister":hex(pc-32),
            "liveStackPointer":"0xffffff8009ba0000"}

def test_image():
    b=bytearray(PC10-w.gate.VM_BASE+300)
    for pc,op,_ in regs.TARGETS.values():
        off=pc-w.gate.VM_BASE
        b[off:off+4]=int(op,16).to_bytes(4,"little")
    return bytes(b)

class CompactFaultSourceWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=test_image()

    def test_original_code_window_includes_measured_ldr(self):
        window=w.stock_window(self.raw,symbols(),PC21)
        self.assertEqual(window["status"],"ORIGINAL_IMAGE_BYTES_BOUNDED_BY_RECOVERED_SYMBOL")
        self.assertEqual(window["nearestRecoveredSymbol"]["name"],"kmem_cache_alloc")
        self.assertTrue(window["includesRecoveredFunctionEntry"])
        words=[e for e in window["sourceWords"] if e["address"]==hex(PC21)]
        self.assertEqual(words,[{"address":hex(PC21),"opcode":"f9402eb8"}])

    def test_second_panic_site_nearest_name_is_candidate_not_proof(self):
        win=w.stock_window(self.raw,symbols(),PC10)
        self.assertEqual(win["nearestRecoveredSymbol"]["name"],"dump_stack_minidump")
        self.assertTrue(win["possibleCodeNotActuallyExecuted"])
        self.assertLessEqual(win["bytes"],w.MAX_WINDOW+256+4)

    def test_long_function_slice_never_exceeds_window(self):
        fake={"entries":[(PC21-0x6000,"T","large_recovered_symbol")]}
        win=w.stock_window(self.raw,fake,PC21)
        self.assertEqual(win["sourceVirtualAddressStart"],hex(PC21-2048))
        self.assertFalse(win["includesRecoveredFunctionEntry"])

    def test_function_far_away_refused(self):
        fake={"entries":[(PC21-0x10000,"T","unrelated")]}
        with self.assertRaisesRegex(w.WindowError,"too distant"):
            w.stock_window(self.raw,fake,PC21)

    def test_preceding_symbol_absent_fails_closed(self):
        with self.assertRaisesRegex(w.WindowError,"unavailable"):
            w.stock_window(self.raw,{"entries":[]},PC21)

    def test_unaligned_and_oversized_code_window_refused(self):
        with self.assertRaisesRegex(w.WindowError,"limit/alignment"):
            w.stock_window(self.raw,symbols(),PC21,back=2049)
        with self.assertRaisesRegex(w.WindowError,"limit/alignment"):
            w.stock_window(self.raw,symbols(),PC21,back=8192)

    def test_saved_original_live_report_and_exact_opcode_both_required(self):
        att={"x21":old_result("x21"),"x10":old_result("x10")}
        with patch.object(w.gate,"valid_source",return_value=None):
            report=w.build(self.raw,att,symbols(),{"allocatorAndDiagnosticFlags":{}},None)
        self.assertEqual(report["status"],"ORIGINAL_COMPACT_ZERO_BASE_FAULT_CODE_WINDOWS_VERIFIED")
        self.assertEqual(report["sites"]["x21"]["originalCodeWindow"]["nearestRecoveredSymbol"]["name"],"kmem_cache_alloc")
        self.assertFalse(report["allocatorInitializationFailureProven"])
        self.assertFalse(report["smcCausedAllocatorFailureProven"])

    def test_nonzero_base_is_not_accepted_as_owner_null_base(self):
        a={"x21":old_result("x21"),"x10":old_result("x10")}
        a["x21"]["liveBaseRegisterValue"]="0x1"
        with patch.object(w.gate,"valid_source",return_value=None):
            with self.assertRaisesRegex(w.WindowError,"not established"):
                w.build(self.raw,a,symbols(),{},None)

    def test_stock_opcode_tamper_rejected(self):
        b=bytearray(self.raw)
        offset=PC21-w.gate.VM_BASE
        b[offset:offset+4]=b"\0"*4
        with patch.object(w.gate,"valid_source",return_value=None):
            with self.assertRaisesRegex(w.WindowError,"differs from live GDB"):
                w.build(bytes(b),{"x21":old_result("x21"),"x10":old_result("x10")},
                        symbols(),{},None)

    def test_stock_config_reports_actual_variant_without_guessing(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/"config.gz"
            with gzip.open(p,"wb") as f:
                f.write(b"CONFIG_SLUB=y\n# CONFIG_SLAB is not set\nCONFIG_SLAB_FREELIST_RANDOM=y\n")
            result=w.read_config(p)
        self.assertEqual(result["allocatorAndDiagnosticFlags"]["CONFIG_SLUB"],"y")
        self.assertTrue(result["configSlabVariantIdentified"])
        self.assertEqual(result["allocatorAndDiagnosticFlags"]["CONFIG_SLAB"],
                         "NOT_ENABLED_OR_NOT_RECORDED")

    def test_ambiguous_config_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/"config.gz"
            with gzip.open(p,"wb") as s:
                s.write(b"CONFIG_SLUB=y\nCONFIG_SLUB=n\n")
            with self.assertRaisesRegex(w.WindowError,"Ambiguous"):
                w.read_config(p)

    def test_missing_or_wrong_config_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/"config.gz"
            with self.assertRaisesRegex(w.WindowError,"missing"):
                w.read_config(p)
            p.write_text("not-gzip")
            with self.assertRaises((OSError,gzip.BadGzipFile)):
                w.read_config(p)

    def test_disassembly_source_register_mentions_not_def_use_proof(self):
        win={"sourceVirtualAddressStart":"0xffffff80082ac900",
             "sourceVirtualAddressEndExclusive":"0xffffff80082ac90c",
             "instructionCount":3}
        output=(
            "ffffff80082ac900: aa0003f5 mov x21, x0\n"
            "ffffff80082ac904: f9402eb8 ldr x24, [x21, #88]\n"
            "ffffff80082ac908: 94000004 bl 0xffffff80082ac918\n")
        fake=subprocess.CompletedProcess(args=[],returncode=0,stdout=output,stderr="")
        with patch.object(w.subprocess,"run",return_value=fake), \
             patch.object(w.Path,"write_bytes",return_value=0):
            result=w.disassemble(win,self.raw,"aarch64-linux-gnu-objdump")
        self.assertEqual(result["status"],"ORIGINAL_FACTORY_IMAGE_DISASSEMBLED")
        self.assertEqual(len(result["registerMentions"]["x21"]),2)
        self.assertFalse(result["registerWriteOriginsEstablished"])

    def test_disassembly_missing_tool_is_non_fatal_and_explicit(self):
        out=w.disassemble({"sourceVirtualAddressStart":"0x10"},self.raw,None)
        self.assertEqual(out["status"],"AARCH64_OBJDUMP_MISSING")
        self.assertEqual(out["registerMentions"],[])

    def test_script_only_offline_and_no_phone_operations(self):
        text=Path(w.__file__).read_text()
        for bad in ("qemu-system-aarch64","adb shell","fastboot flash",
                    "cpu_physical_memory_write","memory_write("):
            self.assertNotIn(bad,text)
        self.assertIn("live.correlate(",text)
        self.assertIn("gate.valid_source(image)",text)

    def test_direct_cli_help_without_repo_as_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=subprocess.run([sys.executable,"-I",str(Path(w.__file__)),"--help"],
                             cwd=tmp,capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn("--config",p.stdout)

if __name__=="__main__":
    unittest.main()
