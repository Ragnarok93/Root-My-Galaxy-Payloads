"""Compile and exercise QEMU-neutral, no-device HXL1 RKP C memory model.

The C model accepts fake guest ranges provided by fixtures only. It does not
implement the UH protocol or reserve guest RAM in QEMU.
"""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/"hxl1_rkp_pool_model.c"
HEADER=ROOT/"hxl1_rkp_pool_model.h"
TEST=ROOT/"hxl1_rkp_pool_model_test.c"
CASE_NAMES=("reservation","allocator","boundary","bitmap","limits")

class Hxl1RkpPoolModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="hxl1-rkp-pool-")
        cls.binary=Path(cls.tmp.name)/"rkp-model-host-test"
        cc=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if cc is None:
            cls.tmp.cleanup()
            raise RuntimeError("Native C compiler required to run RKP prototype tests")
        cmd=[cc,"-std=c11","-O2","-g","-Wall","-Wextra","-Werror",
             "-Wpedantic","-fno-strict-aliasing",str(SOURCE),str(TEST),
             "-o",str(cls.binary)]
        done=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        if done.returncode:
            cls.tmp.cleanup()
            raise AssertionError("RKP model C compile failed:\n"+done.stderr)
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,"tmp"):cls.tmp.cleanup()
    def run_fixture(self,case):
        self.assertTrue(HEADER.exists())
        self.assertEqual(os.path.getsize(SOURCE)>1000,True)
        out=subprocess.run([str(self.binary),case],capture_output=True,
                           text=True,timeout=15)
        self.assertEqual(out.returncode,0,out.stderr+out.stdout)
        self.assertIn("[PASS] host-only RKP "+case,out.stdout)
    def test_pool_must_be_inside_externally_reserved_range(self):
        self.run_fixture("reservation")
    def test_allocation_exhaustion_reuse_and_double_free(self):
        self.run_fixture("allocator")
    def test_one_gib_sparse_unit_boundary(self):
        self.run_fixture("boundary")
    def test_ownership_is_distinct_from_allocation(self):
        self.run_fixture("bitmap")
    def test_input_overflow_and_oversized_pool_rejected(self):
        self.run_fixture("limits")
    def test_no_qemu_or_guest_write_dependencies(self):
        source=SOURCE.read_text()
        header=HEADER.read_text()
        self.assertNotIn("cpu_physical_memory_write",source)
        self.assertNotIn("env->xregs",source)
        self.assertNotIn("UH_APP_RKP",source)
        self.assertIn("No assumed Samsung/Qualcomm physical carveout",header)
    def test_original_bitmap_stride_and_pointer_remain_explicit(self):
        header=HEADER.read_text()
        self.assertIn("#define HXL1_RKP_PAGE_BYTES UINT64_C(4096)",header)
        self.assertIn("#define HXL1_RKP_BITMAP_BYTES_PER_UNIT",header)
        self.assertIn("Guest char **map pointer is NOT populated",header)

if __name__=="__main__":
    unittest.main()
