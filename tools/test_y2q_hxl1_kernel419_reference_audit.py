"""Unit tests for fail-closed cross-device Linux-4.19 source facts."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools import y2q_hxl1_kernel419_reference_audit as m

class Kernel419ReferenceTests(unittest.TestCase):
    def sample(self,root:Path):
        rt=root/"kernel/locking/rtmutex.c"
        rt.parent.mkdir(parents=True)
        rt.write_text("""
static void remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter) {
  raw_spin_lock(&current->pi_lock);
  current->pi_blocked_on = NULL;
}
int rt_mutex_start_proxy_lock(void) {
  if (unlikely(ret))
      remove_waiter(lock, waiter);
}
""")
        fx=root/"kernel/futex.c"
        fx.write_text("static int futex_requeue(void) { return 0; }")

    def test_device_reference_is_not_samsung_or_portable(self):
        self.assertNotEqual(m.HXL1["kernel"],m.REFERENCE["kernel"])
        self.assertNotEqual(m.HXL1["bootHeader"],m.REFERENCE["bootHeader"])
        self.assertFalse(m.REFERENCE["productionOffsetsTransferableToHXL1"])
        self.assertFalse(m.REFERENCE["claimedWorkingRootForHXL1"])

    def test_configfs_four_nineteen_apis_do_not_alias_iterator_calls(self):
        self.assertEqual(m.CALLBACKS["CONFIGFS_READ_FILE_OFF"],"configfs_read_file")
        self.assertEqual(m.CALLBACKS["CONFIGFS_WRITE_BIN_FILE_OFF"],"configfs_write_bin_file")
        self.assertEqual(m.CALLBACKS["CONFIGFS_READ_ITER_OFF"],"configfs_read_iter")
        self.assertEqual(m.CALLBACKS["CONFIGFS_BIN_WRITE_ITER_OFF"],"configfs_bin_write_iter")

    def test_source_path_matches_but_member_identity_not_certified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.sample(root)
            r=m.review(root)
            self.assertEqual(r["status"],"SAMSUNG_419_SOURCE_PATH_PRESENT_ABI_UNVERIFIED")
            self.assertEqual(len(r["checkedSource"]),2)
            self.assertTrue(all(r["patternMatches"].values()))
            self.assertEqual(r["factoryStructOffsetsCertified"],0)
            self.assertFalse(r["stage3Complete"])
            self.assertFalse(r["onDeviceRootVerified"])

    def test_missing_or_altered_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.assertEqual(m.review(root)["status"],"SOURCE_MISSING_OR_UNSAFE")
            self.sample(root)
            (root/"kernel/locking/rtmutex.c").write_text("void unrelated(void) {}")
            self.assertEqual(m.review(root)["status"],"SOURCE_PATTERN_MISMATCH_NEEDS_REVIEW")

    def test_cli_output_is_exclusive_and_nondeployable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.sample(root)
            out=root.parent/("hxl1-test-"+root.name+".json")
            cmd=[sys.executable,str(Path(m.__file__)),"--source",str(root),"--output",str(out)]
            try:
                x=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
                self.assertEqual(x.returncode,0,x.stderr)
                report=json.loads(out.read_text())
                self.assertFalse(report["reference"]["productionOffsetsTransferableToHXL1"])
                self.assertFalse(report["kernelSuDeploymentVerified"])
                self.assertEqual(subprocess.run(cmd,capture_output=True,text=True,timeout=20).returncode,2)
            finally:
                out.unlink(missing_ok=True)

if __name__=="__main__":
    unittest.main()
