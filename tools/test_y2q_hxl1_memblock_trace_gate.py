"""Host-only regression tests for bounded original HXL1 memblock callsite observation.

No factory guest execution or device operations occur in these tests.
"""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_memblock_trace_gate as gate

VA=gate.VM_BASE+0x100
IMAGE=b"\x11\x22\x33\x44"*256
NM=f"{VA:016x} T memblock_reserve\n"

def symbol():
    with patch.object(gate,"KERNEL_SHA",hashlib.sha256(IMAGE).hexdigest()):
        return gate.symbol_probe(NM,IMAGE)

class Hxl1MemblockGateTests(unittest.TestCase):
    def test_exact_recovered_symbol_opcode_anchored_to_original_bytes(self):
        r=symbol()
        self.assertEqual(r["guestVirtualAddress"],hex(VA))
        self.assertEqual(r["originalFirstOpcode"],"0x44332211")
        self.assertIn("NOT_INDEPENDENT_RUNTIME_SYMBOL",r["symbolTrust"])
    def test_modified_factory_image_rejected(self):
        with self.assertRaisesRegex(gate.GateError,"SHA256 mismatch"):
            gate.symbol_probe(NM,IMAGE)
    def test_ambiguous_and_outside_symbol_rejected(self):
        with patch.object(gate,"KERNEL_SHA",hashlib.sha256(IMAGE).hexdigest()):
            with self.assertRaisesRegex(gate.GateError,"exactly one"):
                gate.symbol_probe(NM+NM,IMAGE)
            with self.assertRaisesRegex(gate.GateError,"outside"):
                gate.symbol_probe("ffffff8009000000 T memblock_reserve\n",IMAGE)
    def test_empty_and_four_nops_symbols_rejected(self):
        for b in (bytes(1024),bytes.fromhex("1f2003d5")*256):
            with patch.object(gate,"KERNEL_SHA",hashlib.sha256(b).hexdigest()):
                with self.assertRaisesRegex(gate.GateError,"distinguishing"):
                    gate.symbol_probe(NM,b)
    def test_gdb_script_is_read_only_and_conditional(self):
        s=gate.build_gdb(12579,VA,0x44332211)
        self.assertIn(f"hbreak *{hex(gate.KERNEL_ENTRY_PC)}",s)
        self.assertIn("HXL1_KERNEL_ENTRY_HIT",s)
        self.assertIn(f"hbreak *{hex(VA)} if $x0 == 0x48000000",s)
        self.assertIn(f"hbreak *{hex(gate.SMC_PC)}",s)
        self.assertIn("x/wx $pc",s)
        self.assertNotIn("set {",s)
        self.assertNotIn("restore ",s)
        self.assertNotIn("shell ",s)
    def test_exact_callsite_and_fdt_arguments_without_false_allocator_proof(self):
        sym=symbol()
        log=(f"HXL1_KERNEL_ENTRY_HIT PC={hex(gate.KERNEL_ENTRY_PC)} X0=0x48000000\n"+
             f"HXL1_MEMBLOCK_RESERVE_HIT PC={hex(VA)} "
             "X0=0x48000000 X1=0x205000\n"
             f"0x{VA:x}:\t0x44332211\n")
        r=gate.parse_gdb(log,sym)
        self.assertEqual(r["status"],"STOCK_MEMBLOCK_RESERVE_ENTRY_ARGS_OBSERVED")
        self.assertTrue(r["requestedSizeCoversV3PageAlignedReserve"])
        self.assertFalse(r["actualAllocatorReservationVerified"])
        self.assertFalse(r["functionReturnedSuccessfully"])
    def test_wrong_original_opcode_and_wrong_pc_not_correlated(self):
        sym=symbol()
        for log in (
            f"HXL1_MEMBLOCK_RESERVE_HIT PC={hex(VA)} X0=0x48000000 X1=0x205000\n"
            f"0x{VA:x}:\t0xaabbccdd\n",
            f"HXL1_MEMBLOCK_RESERVE_HIT PC={hex(VA+4)} X0=0x48000000 X1=0x205000\n"
            f"0x{VA+4:x}:\t0x44332211\n",
        ):
            r=gate.parse_gdb(
                f"HXL1_KERNEL_ENTRY_HIT PC={hex(gate.KERNEL_ENTRY_PC)} X0=0x48000000\n"+log,sym)
            self.assertFalse(r["memblockReserveCallObserved"])
    def test_smc_stop_is_not_false_negative_about_memblock(self):
        r=gate.parse_gdb(
            f"HXL1_KERNEL_ENTRY_HIT PC={hex(gate.KERNEL_ENTRY_PC)} X0=0x48000000\n"
            f"HXL1_SMC_REACHED PC={hex(gate.SMC_PC)}\n",symbol())
        self.assertFalse(r["memblockReserveCallObserved"])
        self.assertTrue(r["doesNotProveCallAbsent"])
    def test_missing_breakpoint_cannot_claim_observation(self):
        r=gate.parse_gdb("GDB_BOUNDED_TIMEOUT\n",symbol())
        self.assertEqual(r["status"],"TIMEOUT_BEFORE_KERNEL_ENTRY_OR_GDB_STOP")
    def test_smc_before_entry_is_not_guest_kernel_evidence(self):
        r=gate.parse_gdb(
            f"HXL1_SMC_REACHED PC={hex(gate.SMC_PC)}\n",symbol())
        self.assertFalse(r["kernelEntryObserved"])
        self.assertFalse(r["memblockReserveCallObserved"])

    def test_entry_without_memblock_or_smc_remains_inconclusive(self):
        r=gate.parse_gdb(
            f"HXL1_KERNEL_ENTRY_HIT PC={hex(gate.KERNEL_ENTRY_PC)} X0=0x48000000\n"
            "GDB_BOUNDED_TIMEOUT\n",symbol())
        self.assertTrue(r["kernelEntryObserved"])
        self.assertEqual(r["status"],"POST_ENTRY_EXECUTION_TIMEOUT")
        self.assertFalse(r["actualAllocatorReservationVerified"])

    def test_wrong_guest_entry_fdt_pointer_fails_before_trust(self):
        r=gate.parse_gdb(
            f"HXL1_KERNEL_ENTRY_HIT PC={hex(gate.KERNEL_ENTRY_PC)} X0=0x48001000\n"
            f"HXL1_MEMBLOCK_RESERVE_HIT PC={hex(VA)} X0=0x48000000 X1=0x205000\n"
            f"0x{VA:x}:\t0x44332211\n",symbol())
        self.assertEqual(r["status"],"ENTRY_POINTER_OR_PC_MISMATCH")
        self.assertFalse(r["memblockReserveCallObserved"])

    def test_gdb_protocol_error_not_misclassified_as_no_call(self):
        r=gate.parse_gdb("Remote connection closed\nGDB_BOUNDED_TIMEOUT\n",symbol())
        self.assertEqual(r["status"],"GDB_OR_BREAKPOINT_SETUP_ERROR")
        self.assertFalse(r["kernelEntryObserved"])

    def test_saved_v1_timeout_log_auditable_without_qemu(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"gdb.log").write_text(
                "Hardware assisted breakpoint 1\nGDB_BOUNDED_TIMEOUT\n")
            (root/"gdb-exit-code.txt").write_text("124\n")
            (root/"qemu.log").write_text("VM log placeholder\n")
            report=gate.audit_saved_probe(root)
            self.assertTrue(report["timeoutObserved"])
            self.assertFalse(report["kernelEntryProof"])
            self.assertEqual(report["gdbExitCode"],"124")
            self.assertFalse(report["linuxMemblockAllocatorExclusionVerified"])

    def test_output_must_be_fresh_under_research_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"research"
            root.mkdir()
            self.assertEqual(gate.safe_output(root/"fresh",root),root/"fresh")
            with self.assertRaisesRegex(gate.GateError,"subdirectory"):
                gate.safe_output(Path(d)/"outside",root)
            existing=root/"existing"
            existing.mkdir()
            with self.assertRaisesRegex(gate.GateError,"exists"):
                gate.safe_output(existing,root)
    def test_target_only_isolated_no_device_tools(self):
        s=Path(gate.__file__).read_text()
        for banned in ("adb shell","fastboot flash","heimdall flash",
                       "subprocess.Popen(['adb'", "root@"):
            self.assertNotIn(banned,s)
        self.assertIn('"-nic","none"',s)
        self.assertIn("proc.terminate()",s)
        self.assertIn("proc.kill()",s)

if __name__=="__main__":
    unittest.main()
