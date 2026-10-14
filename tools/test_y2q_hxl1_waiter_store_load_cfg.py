"""Synthetic, no-device regression tests for original HXL1 waiter store/load CFG."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import y2q_hxl1_waiter_store_load_cfg as m

SRC=b"""struct futex_q {
 struct rt_mutex_waiter *rt_waiter;
} __randomize_layout;
q.rt_waiter = &rt_waiter;
if (!q.rt_waiter) {
ret = rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);
if (ret && !rt_mutex_cleanup_proxy_lock(pi_mutex, &rt_waiter))
"""

def fixture():
    rows={m.BASE+i*4:("d503201f","nop","") for i in range(1766)}
    for off,item in m.REQUIRED.items():
        rows[m.BASE+off]=item
    return rows

def text_fixture(rows):
    return ("\n".join(f"{addr:016x}:\t{word}\t{op}\t{args}"
                       for addr,(word,op,args) in sorted(rows.items()))+"\n").encode()

class StoreLoadStaticTests(unittest.TestCase):
    def test_synthetic_source_anchors(self):
        self.assertEqual(len(m.source_anchors(SRC)),6)

    def test_source_annotation_not_oem_layout_proof(self):
        r=m.audit(SRC,text_fixture(fixture()))
        self.assertFalse(r["stockCompilerActualRandstructReorderingVerified"])
        self.assertFalse(r["samePhysicalPointerLiveAcrossAllCallsProven"])

    def test_synthetic_contiguous_instruction_parse(self):
        self.assertEqual(len(m.parse(text_fixture(fixture()))),1766)

    def test_pinned_instruction_signature_check(self):
        self.assertTrue(m.validate_sites(fixture()))

    def test_synthetic_store_load_static_path(self):
        r=m.audit(SRC,text_fixture(fixture()))
        self.assertTrue(r["staticControlFlowPathStoreToLoadFound"])
        self.assertEqual(r["storeFirstMemorySlot"],"SP + 0xa0")
        self.assertEqual(r["laterLoadedSecondRegister"],"x9")

    def test_branch_has_two_possible_cfg_successors(self):
        r=fixture()
        self.assertEqual(m.successors(r,m.BASE+0x12f0),
                         [m.BASE+0x12f4,0xffffff800818f9e0])

    def test_mutated_original_store_rejected(self):
        r=fixture()
        r[m.BASE+0x11d0]=("00000000","stp","x25, x27, [sp, #160]")
        with self.assertRaisesRegex(m.AuditError,"drift"):
            m.validate_sites(r)

    def test_mutated_original_load_rejected(self):
        r=fixture()
        r[m.BASE+0x12ec]=("a949a7e8","ldp","x8, x10, [sp, #152]")
        with self.assertRaisesRegex(m.AuditError,"drift"):
            m.validate_sites(r)

    def test_swapped_null_branch_rejected(self):
        r=fixture()
        r[m.BASE+0x12f0]=("b4000e29","cbnz","x9, 0xffffff800818f9e0")
        with self.assertRaisesRegex(m.AuditError,"drift"):
            m.validate_sites(r)

    def test_removed_source_waiter_check_rejected(self):
        with self.assertRaisesRegex(m.AuditError,"anchors"):
            m.source_anchors(SRC.replace(b"if (!q.rt_waiter) {",
                                         b"if (pi_state) {"))

    def test_missing_instruction_rejected(self):
        r=fixture()
        r.pop(m.BASE+0x600)
        with self.assertRaisesRegex(m.AuditError,"window changed"):
            m.parse(text_fixture(r))

    def test_unreachable_cfg_path_rejected(self):
        r=fixture()
        r[m.BASE+0x11d0]=("d65f03c0","ret","")
        with self.assertRaisesRegex(m.AuditError,"static CFG path"):
            m.shortest_static_path(r,m.BASE+0x11d0,m.BASE+0x12ec)

    def test_out_of_range_direct_branch_not_invented(self):
        r={m.BASE:("14000000","b","0xffffff8009000000")}
        self.assertEqual(m.successors(r,m.BASE),[])

    def test_invalid_cfg_endpoint_rejected(self):
        with self.assertRaisesRegex(m.AuditError,"endpoints"):
            m.shortest_static_path(fixture(),m.BASE+0xf00,m.BASE+0xffffff)

    def test_standalone_cli_imports_from_external_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cmd=[sys.executable,"-I",str(Path(m.__file__).resolve()),"--help"]
            r=subprocess.run(cmd,cwd=tmp,capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("--disassembly-archive",r.stdout)

if __name__=="__main__":
    unittest.main()
