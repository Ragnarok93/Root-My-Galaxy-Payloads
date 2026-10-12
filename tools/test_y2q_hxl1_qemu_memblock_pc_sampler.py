"""No-QEMU fixture tests for bounded, original-image read-only QMP CPU samples."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_qemu_memblock_pc_sampler as sampler


class Hxl1QmpPcSamplerTests(unittest.TestCase):
    def test_pc_register_captured_with_arm_esr_far_elr(self):
        raw=("CPU 0\n"
             "PC=ffffff80082a0844 SP=ffffff800a123000\n"
             "ELR_EL1=ffffff80080a5794\n"
             "ESR_EL1=0000000096000004 FAR_EL1=000000003ffffffc\n")
        r=sampler.register_snapshot(raw)
        self.assertEqual(r["pc"],"0xffffff80082a0844")
        self.assertEqual(r["elr"]["1"],"0xffffff80080a5794")
        self.assertEqual(r["far"]["1"],"0x000000003ffffffc")
        self.assertFalse(r["rawTruncated"])

    def test_no_pcs_not_fabricated(self):
        raw="invalid read at addr 0x3FFFFFFC\n"
        result=sampler.register_snapshot(raw)
        self.assertIsNone(result["pc"])
        self.assertEqual(result["pcMatches"],0)

    def test_multiple_pcs_marked_ambiguous(self):
        r=sampler.register_snapshot("PC=0000000040080000\nPC=ffffff80080a5794\n")
        self.assertIsNone(r["pc"])
        self.assertEqual(r["pcMatches"],2)

    def test_pc_samples_do_not_prove_loop_or_memblock(self):
        samples=[
            {"registers":{"pc":"0xffffff80082ac90c"}},
            {"registers":{"pc":"0xffffff80082ac90c"}},
        ]
        r=sampler.classify(samples,"v3-canary")
        self.assertEqual(r["status"],"SAME_PC_IN_MULTIPLE_SNAPSHOTS")
        self.assertTrue(r["cannotInferInfiniteLoopFromIdenticalSamples"])
        self.assertFalse(r["linuxMemblockAllocatorExclusionVerified"])
        self.assertFalse(r["kernelEntryReachedDuringThisSamplingRun"])

    def test_progression_is_not_linux_boot_claim(self):
        r=sampler.classify([
            {"registers":{"pc":"0x40080000"}},
            {"registers":{"pc":"0xffffff80080a5794"}},
        ],"v3-canary")
        self.assertEqual(r["status"],"GUEST_PC_CHANGED_ACROSS_SNAPSHOTS")
        self.assertFalse(r["rkpProtectedPoolConfirmed"])

    def test_no_observation_remains_unverified(self):
        r=sampler.classify([{"error":"QMP unsupported"}],"baseline")
        self.assertEqual(r["status"],"GUEST_PC_UNAVAILABLE")
        self.assertEqual(r["pcSequence"],[])

    def test_original_qemu_profile_and_v3_override(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            kernel=root/"kernel.bin"
            can=root/"canary.dtb"
            out=root/"capture"
            command=sampler.build_qemu_command(kernel,can,out,"v3-canary")
            self.assertIn("-dtb",command)
            self.assertIn(str(can),command)
            self.assertIn("-S",command)
            self.assertIn("-nic",command)
            self.assertIn("none",command)
            self.assertIn("-qmp",command)
            self.assertTrue(any(x.startswith("unix:") for x in command))
            self.assertIn("-d",command)

    def test_baseline_omits_dt_override_but_still_factory_source(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            kernel=root/"kernel.bin"
            command=sampler.build_qemu_command(kernel,root/"canary.dtb",
                                               root/"output","baseline")
            self.assertNotIn("-dtb",command)
            self.assertIn("-kernel",command)
            self.assertIn(str(kernel),command)
            self.assertIn("-nic",command)

    def test_log_tail_bounded_to_last_6000_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"log"
            p.write_bytes(b"A"*50000+b"last read at 0x3FFFFFFC\n")
            out=sampler.log_tail(p)
            self.assertEqual(out["sizeBytes"],50024)
            self.assertNotIn("A"*8000,out["tail"])
            self.assertIn("0x3FFFFFFC",out["tail"])

    def test_qmp_commands_and_response_id_checked(self):
        class FakeQmp(sampler.QMP):
            def __init__(self):
                self.id=0
                self.sent=[]
                self.events=[]
            def _recv(self):
                return {"id":"wrong-id","return":{}}
        fake=FakeQmp()
        class FakeWriter:
            def __init__(self):self.raw=None
            def write(self,b):self.raw=b
        fake.stream=FakeWriter()
        with self.assertRaisesRegex(sampler.MonitorError,"ID mismatch"):
            fake.request("query-status")
        self.assertEqual(json.loads(fake.stream.raw)["execute"],"query-status")

    def test_sampler_source_no_guest_memory_writes_or_phone_commands(self):
        source=Path(sampler.__file__).read_text()
        for bad in ("fastboot flash", "adb shell", "cpu_physical_memory_write",
                    "dump-guest-memory", "memory_write"):
            self.assertNotIn(bad,source)
        self.assertIn("proc.terminate()",source)
        self.assertIn("proc.kill()",source)
        self.assertIn("human-monitor-command",source)

if __name__=="__main__":
    unittest.main()
