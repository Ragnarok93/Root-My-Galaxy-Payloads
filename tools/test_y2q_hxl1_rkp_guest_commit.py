"""Compile and test rollback-safe HOST-ONLY guest-RKP memory transaction.

Tests use a small sparse simulated guest PA backend with an optimistic, known
fictional VA mapping. This does NOT reserve QEMU RAM or validate its MMU.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
FILES=tuple(ROOT/x for x in (
    "hxl1_rkp_pool_model.c",
    "hxl1_rkp_guest_stage.c",
    "hxl1_rkp_guest_commit.c",
    "hxl1_rkp_guest_commit_test.c",
))
FIXTURES=(
    "success","partial","rollback-fail","dirty",
    "mapping","readback","preconditions",
)

class Hxl1RkpGuestCommitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="hxl1-rkp-transaction-")
        cls.binary=Path(cls.temp.name)/"hxl1-guest-commit-fixture"
        cc=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if cc is None:
            cls.temp.cleanup()
            raise RuntimeError("Native C compiler required")
        command=[
            cc,"-std=c11","-O2","-g","-Wall","-Wextra","-Werror",
            "-Wpedantic","-fno-strict-aliasing",
            *map(str,FILES),"-o",str(cls.binary),
        ]
        result=subprocess.run(command,capture_output=True,text=True,timeout=30)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError("HXL1 transaction failed to compile:\n"+result.stderr)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,"temp"):
            cls.temp.cleanup()

    def verify(self,fixture):
        process=subprocess.run(
            [str(self.binary),fixture],
            capture_output=True,text=True,timeout=15)
        self.assertEqual(process.returncode,0,process.stderr+process.stdout)
        self.assertIn("[PASS] host-only transactional RKP "+fixture,
                      process.stdout)

    def test_good_commit_pointer_published_last(self):
        self.verify("success")
    def test_partial_write_rolls_back_every_attempted_region(self):
        self.verify("partial")
    def test_unrecoverable_rollback_detected(self):
        self.verify("rollback-fail")
    def test_dirty_backing_and_initialized_pointer_rejected(self):
        self.verify("dirty")
    def test_mapping_failure_mid_commit_rolls_back(self):
        self.verify("mapping")
    def test_readback_corruption_rolls_back(self):
        self.verify("readback")
    def test_quiescence_and_physical_reservation_gates(self):
        self.verify("preconditions")
    def test_no_direct_qemu_guest_access_is_implemented(self):
        source=(ROOT/"hxl1_rkp_guest_commit.c").read_text()
        self.assertNotIn("address_space_write",source)
        self.assertNotIn("cpu_physical_memory_write",source)
        self.assertNotIn("env->xregs",source)
        self.assertIn("restore_attempted",source)
        header=(ROOT/"hxl1_rkp_guest_commit.h").read_text()
        self.assertIn("all_vcpus_quiesced",header)
        self.assertIn("ram_reservation_verified",header)
        self.assertIn("HXL1_RKP_COMMIT_ROLLBACK_FAILED",header)

if __name__=="__main__":
    unittest.main()
