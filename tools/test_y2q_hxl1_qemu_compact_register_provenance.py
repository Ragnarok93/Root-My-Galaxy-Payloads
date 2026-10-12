"""Offline regressions for HXL1 staged producer-to-fault QEMU GDB probes."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_qemu_compact_register_provenance as p


def log_for(target="x21",producer=True,fault=True,source_base=0,base=0):
    c=p.CANDIDATES[target]
    raw=(
        "Breakpoint 1, 0x40080000 in ?? ()\n"
        "HXL1_ORIG_ENTRY PC=0x40080000 FDT=0x48000000\n"
        "HXL1_ORIG_SMC PC=0xffffff80080a5794 X0=0xc300c002 X1=0x15 X2=0xffffff800a4dd0b8 X3=0x40000000\n"
        "0xffffff80080a5794:\t0xd4000003\n"
    )
    if producer:
        raw+=(
            f"HXL1_REG_PRODUCER PC={hex(c['producer'])} "
            f"SOURCE_BASE={hex(source_base)} BEFORE=0x0 SP=0xffffff800abc0000\n"
            f"{hex(c['producer'])}:\t0x{c['producerOpcode']}\n"
        )
    if fault:
        raw+=(
            f"HXL1_REG_FAULT PC={hex(c['fault'])} BASE={hex(base)} "
            "SP=0xffffff800abc0000 LR=0xffffff80082ac83c\n"
            f"{hex(c['fault'])}:\t0x{c['faultOpcode']}\n"
        )
    return raw

def original_synthetic_bytes():
    v=max(c["fault"] for c in p.CANDIDATES.values())-p.gate.VM_BASE
    data=bytearray(v+8)
    for c in p.CANDIDATES.values():
        for key,w in (("producer",c["producerOpcode"]),("fault",c["faultOpcode"])):
            off=c[key]-p.gate.VM_BASE
            data[off:off+4]=int(w,16).to_bytes(4,"little")
    return bytes(data)

class RegisterProvenanceTests(unittest.TestCase):
    def test_original_x21_saved_stack_pointer(self):
        report=p.analyze(log_for("x21",source_base=0xffffff800abc0000),"x21")
        self.assertEqual(report["status"],"PRODUCER_THEN_FAULT_OBSERVED_NO_FULL_DEF_USE_PROOF")
        self.assertEqual(report["producerSourceEffectiveAddress"],"0xffffff800abc0048")
        self.assertEqual(report["faultBaseValueBefore"],"0x0")
        self.assertFalse(report["completeRegisterDataFlowProven"])

    def test_original_x10_pointer_field(self):
        report=p.analyze(log_for("x10",source_base=0xffffff800a000000),"x10")
        self.assertEqual(report["producerSourceEffectiveAddress"],"0xffffff800a000b18")
        self.assertTrue(report["producerObservedInThisRun"])
        self.assertTrue(report["faultObservedInThisRun"])
        self.assertFalse(report["allocatorCachePointerIdentified"])

    def test_first_fault_without_producer_not_falsely_excluded(self):
        r=p.analyze(log_for("x21",producer=False),"x21")
        self.assertEqual(r["status"],"FAULT_CAPTURED_PRODUCER_NOT_OBSERVED")
        self.assertFalse(r["producerObservedInThisRun"])
        self.assertTrue(r["faultObservedInThisRun"])

    def test_producer_only_not_success(self):
        r=p.analyze(log_for("x10",fault=False),"x10")
        self.assertEqual(r["status"],"PRODUCER_CAPTURED_FAULT_NOT_OBSERVED")
        self.assertFalse(r["faultObservedInThisRun"])

    def test_no_producer_and_no_fault_timeout_stays_inconclusive(self):
        r=p.analyze(log_for("x10",producer=False,fault=False)+
                    "GDB_BOUNDED_TIMEOUT\n","x10")
        self.assertEqual(r["status"],"NO_PRODUCER_OR_FAULT_BREAKPOINT_IN_BOUNDED_RUN")
        self.assertFalse(r["completeRegisterDataFlowProven"])

    def test_invalid_smc_function_id_rejected(self):
        changed=log_for().replace("X0=0xc300c002","X0=0xc300c003")
        r=p.analyze(changed,"x21")
        self.assertEqual(r["status"],"ORIGINAL_RKP_SMC_NOT_VALIDATED")

    def test_wrong_smc_instruction_rejected(self):
        changed=log_for().replace("0xd4000003","0xd503201f")
        r=p.analyze(changed,"x21")
        self.assertEqual(r["status"],"RUNTIME_SMC_OPCODE_NOT_VERIFIED")

    def test_wrong_producer_opcode_rejected(self):
        changed=log_for().replace("0xa94457f6","0xd503201f")
        r=p.analyze(changed,"x21")
        self.assertEqual(r["status"],"RUNTIME_PRODUCER_OPCODE_MISMATCH")

    def test_wrong_fault_opcode_rejected(self):
        changed=log_for().replace("0xa9412149","0xd503201f")
        r=p.analyze(changed,"x10")
        self.assertEqual(r["status"],"RUNTIME_FAULT_OPCODE_MISMATCH")

    def test_duplicate_producer_does_not_prove_same_run_source(self):
        changed=log_for()
        marker=changed[changed.index("HXL1_REG_PRODUCER"):changed.index("HXL1_REG_FAULT")]
        result=p.analyze(changed+marker,"x21")
        self.assertEqual(result["status"],"AMBIGUOUS_DUPLICATE_GDB_STOPS")

    def test_wrong_order_cannot_claim_producer_first(self):
        raw=log_for("x21")
        earlier=raw[raw.index("HXL1_REG_PRODUCER"):raw.index("HXL1_REG_FAULT")]
        later=raw[raw.index("HXL1_REG_FAULT"):]
        head=raw[:raw.index("HXL1_REG_PRODUCER")]
        r=p.analyze(head+later+earlier,"x21")
        self.assertEqual(r["status"],"STOP_ORDER_INCONSISTENT")
        self.assertFalse(r["faultObservedInThisRun"])

    def test_stock_opcode_pin_both_addresses(self):
        with patch.object(p.gate,"valid_source",return_value=None):
            for t in p.CANDIDATES:
                r=p.verify_stock_words(original_synthetic_bytes(),t)
                self.assertEqual(r["producerOpcode"],p.CANDIDATES[t]["producerOpcode"])
                self.assertEqual(r["faultOpcode"],p.CANDIDATES[t]["faultOpcode"])

    def test_factory_producer_mutation_fails_closed(self):
        raw=bytearray(original_synthetic_bytes())
        off=p.CANDIDATES["x21"]["producer"]-p.gate.VM_BASE
        raw[off:off+4]=b"\0"*4
        with patch.object(p.gate,"valid_source",return_value=None):
            with self.assertRaisesRegex(p.ProvenanceError,"differ"):
                p.verify_stock_words(bytes(raw),"x21")

    def test_gdb_stage_is_temporary_and_readonly(self):
        for t,c in p.CANDIDATES.items():
            source=p.script(12357,t)
            self.assertIn("thbreak *0xffffff80080a5794",source)
            self.assertIn("thbreak *"+hex(c["producer"]),source)
            self.assertIn("thbreak *"+hex(c["fault"]),source)
            self.assertLess(source.index("thbreak *"+hex(c["producer"])),
                            source.index("thbreak *"+hex(c["fault"])))
            self.assertIn("x/1wx $pc",source)
            self.assertIn("x/1gx ",source)
            self.assertNotIn("set {",source)
            self.assertNotIn("restore ",source)

    def test_user_device_and_source_immutability(self):
        source=Path(p.__file__).read_text()
        for banned in ("fastboot flash","adb shell","cpu_physical_memory_write",
                       "memory_write("):
            self.assertNotIn(banned,source)
        self.assertIn("smc.verify_preflight",source)
        self.assertIn("proc.kill()",source)
        self.assertIn('"-nic","none"',source)

    def test_script_help_in_isolated_python(self):
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([sys.executable,"-I",str(Path(p.__file__)),"--help"],
                             cwd=d,capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("--preflight-only",r.stdout)
        self.assertIn("--target",r.stdout)

if __name__=="__main__":
    unittest.main()
