"""Compile QEMU-neutral original HXL1 guest bitmap descriptor serialization model.

Only exercises fake VA-to-PA mappings and host buffers; no guest RAM is
allocated or written, no emulator is started, and the phone remains untouched.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
SOURCES=[
    ROOT/"hxl1_rkp_pool_model.c",
    ROOT/"hxl1_rkp_guest_stage.c",
    ROOT/"hxl1_rkp_guest_stage_test.c"
]

class Hxl1RkpGuestStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="hxl1-rkp-descriptor-")
        cls.executable=Path(cls.temp.name)/"test_hxl1_descriptor"
        cc=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            cls.temp.cleanup()
            raise RuntimeError("C compiler required")
        compile_cmd=[
            cc,"-std=c11","-O2","-g","-Wall","-Wextra","-Werror",
            "-Wpedantic","-fno-strict-aliasing",
            *map(str,SOURCES),"-o",str(cls.executable)
        ]
        result=subprocess.run(compile_cmd,capture_output=True,text=True,timeout=30)
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError("Native C staging model failed to compile:\n"+result.stderr)
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,"temp"):cls.temp.cleanup()
    def check_case(self,name):
        result=subprocess.run([str(self.executable),name],
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn("host-only descriptor staging "+name,result.stdout)
    def test_descriptor_le64_pointer_chain(self):
        self.check_case("layout")
    def test_unknown_guest_mapping_fails_closed(self):
        self.check_case("mapping")
    def test_unreserved_alias_truncation_and_overflow(self):
        self.check_case("safety")
    def test_double_staging_and_cleanup(self):
        self.check_case("lifetime")
    def test_host_only_with_no_direct_guest_writes(self):
        text=(ROOT/"hxl1_rkp_guest_stage.c").read_text()
        self.assertNotIn("cpu_physical_memory_write",text)
        self.assertNotIn("address_space_write",text)
        self.assertNotIn("env->xregs",text)
        self.assertIn("if (!verify(opaque,",text)
    def test_guest_global_pointer_not_replaced_without_mapping(self):
        text=(ROOT/"hxl1_rkp_guest_stage.h").read_text()
        self.assertIn("guest page tables / QEMU address space",text)
        self.assertIn("global_slot",text)
        self.assertIn("No rollback/transaction guarantees",text)

if __name__=="__main__":
    unittest.main()
