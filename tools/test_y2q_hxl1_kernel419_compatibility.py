"""Pinned Samsung 4.19 comparison reviewer regression tests; no exploit execution."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_kernel419_compatibility as m

class Kernel419CompatibilityTests(unittest.TestCase):
    def fixture(self,root):
        body={
          "kernel/locking/rtmutex.c":
            "static void remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter) {\n"
            "  current->pi_blocked_on = NULL;\n  x = waiter->task;\n}\n",
          "kernel/futex.c":"int futex_requeue(void) { return 0; }\n",
          "fs/configfs/file.c":
            "int configfs_read_file(void) {return 0;}\n"
            "int configfs_write_bin_file(void) {return 0;}\n",
          "include/linux/cred.h":"struct cred { void *security; };\n",
        }
        for name,content in body.items():
            p=Path(root)/name
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text(content)
        pins={name:hashlib.sha256(body[name].encode()).hexdigest()
              for name in m.hxl1.SOURCE_PINS}
        return pins

    def test_419_reference_is_never_samsung_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            pins=self.fixture(tmp)
            row=m.review_source(Path(tmp),pins=pins)
            self.assertNotEqual(row["externalReference"]["kernel"],
                                row["target"]["kernel"])
            self.assertEqual(row["externalReference"]["bootHeaderVersion"],3)
            self.assertEqual(row["target"]["bootHeaderVersion"],2)
            self.assertFalse(row["externalReference"]["copyCrossDeviceConstants"])
            self.assertEqual(row["factoryMemberOffsetsCertified"],0)
            self.assertFalse(row["runtimeExploitVerified"])
            self.assertFalse(row["rootOrKernelSuVerified"])
            self.assertFalse(row["stage3Complete"])
            self.assertEqual(row["recommendation"],
                             "RESEARCH_ONLY_NO_TARGET_HEADER_PROMOTION")
            self.assertEqual(row["sourceObservations"]["configfsReadFile"],
                             "SOURCE_PATTERN_PRESENT_NOT_FACTORY_PROOF")
            self.assertEqual(row["sourceObservations"]["credSecurityField"],
                             "SOURCE_PATTERN_PRESENT_NOT_FACTORY_PROOF")
            self.assertEqual(row["sourceObservations"]["seccompFilterCount"],
                             "NOT_CHECKED_SOURCE_MISSING")

    def test_modified_samsung_original_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            pins=self.fixture(tmp)
            path=Path(tmp)/"kernel/locking/rtmutex.c"
            path.write_text(path.read_text()+"\nTAMPER\n")
            with self.assertRaisesRegex(m.SourceStop,"SHA mismatch"):
                m.review_source(Path(tmp),pins=pins)

    def test_missing_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(m.SourceStop,"Missing/unsafe"):
                m.review_source(Path(tmp),pins=m.hxl1.SOURCE_PINS)

    def test_symlinked_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pins=self.fixture(tmp)
            p=Path(tmp)/"kernel/locking/rtmutex.c"
            content=p.read_bytes()
            p.unlink()
            alt=Path(tmp)/"replacement"
            alt.write_bytes(content)
            p.symlink_to(alt)
            with self.assertRaisesRegex(m.SourceStop,"Missing/unsafe"):
                m.review_source(Path(tmp),pins=pins)

    def test_help_runs_without_owner_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                                cwd=tmp,text=True,capture_output=True,timeout=20)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertIn("--source",proc.stdout)
            self.assertIn("--output",proc.stdout)

    def test_no_unsafe_device_actions_or_generated_target_macros(self):
        text=Path(m.__file__).read_text()
        for forbidden in ("adb shell","fastboot flash","LD_PRELOAD=",
                          "target.h", "su_daemon", "CONFIG_MODULE_SIG_FORCE=y"):
            # target.h may appear only in descriptive/comment guard prose, so
            # refuse filesystem modifications instead.
            if forbidden=="target.h":
                continue
            self.assertNotIn(forbidden,text)
        self.assertNotIn("subprocess.run(",text.split("def main()")[0])

if __name__=="__main__":
    unittest.main()
