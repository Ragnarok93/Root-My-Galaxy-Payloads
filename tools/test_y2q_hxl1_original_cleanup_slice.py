"""Offline tests for HXL1 verbatim original-Samsung-source cleanup regression."""
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_original_cleanup_slice as testee

SAMPLE = r'''
/* test parser: closing brace in comment } must be ignored */
static void remove_waiter(struct rt_mutex *lock,
                          struct rt_mutex_waiter *waiter)
{
    bool is_top_waiter = (waiter == rt_mutex_top_waiter(lock));
    struct task_struct *owner = rt_mutex_owner(lock);
    struct rt_mutex *next_lock;
    lockdep_assert_held(&lock->wait_lock);
    raw_spin_lock(&current->pi_lock);
    rt_mutex_dequeue(lock, waiter);
    current->pi_blocked_on = NULL;
    raw_spin_unlock(&current->pi_lock);
    if (!owner || !is_top_waiter)
        return;
    raw_spin_lock(&owner->pi_lock);
    rt_mutex_dequeue_pi(owner, waiter);
    if (rt_mutex_has_waiters(lock))
        rt_mutex_enqueue_pi(owner, rt_mutex_top_waiter(lock));
    rt_mutex_adjust_prio(owner);
    next_lock = task_blocked_on_lock(owner);
    raw_spin_unlock(&owner->pi_lock);
    if (!next_lock)
        return;
    get_task_struct(owner);
    raw_spin_unlock_irq(&lock->wait_lock);
    rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock,
                               next_lock, NULL, current);
    raw_spin_lock_irq(&lock->wait_lock);
}
'''

class OriginalSliceTests(unittest.TestCase):
    def test_verbatim_source_extracted_and_native_executed(self):
        if not shutil.which("cc"): self.skipTest("No compiler")
        original=testee.extract_function(SAMPLE)
        self.assertIn("current->pi_blocked_on = NULL;",original)
        result=testee.execute(testee.STUBS+"\n"+original+"\n"+testee.TRAILER,"cc",None)
        self.assertEqual(len(result["observations"]),2)
        self.assertFalse(result["observations"][1]["waiterTaskCleared"])
    def test_undeclared_function_rejected(self):
        with self.assertRaisesRegex(testee.OriginalSourceError,"Expected one"):
            testee.extract_function("int unrelated(void) { return 1; }")
    def test_corrected_source_must_not_masquerade_as_stock(self):
        with self.assertRaisesRegex(testee.OriginalSourceError,"current-task cleanup"):
            testee.extract_function(SAMPLE.replace("current->pi_blocked_on = NULL;",
                "waiter->task->pi_blocked_on = NULL;"))
    def test_unclosed_source_rejected(self):
        with self.assertRaisesRegex(testee.OriginalSourceError,"Truncated"):
            testee.extract_function(SAMPLE.rstrip()[:-1])
    def test_sha_pin_and_false_kernel_promotion(self):
        if not shutil.which("cc"): self.skipTest("No compiler")
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            f=root/testee.SOURCE_REL
            f.parent.mkdir(parents=True)
            f.write_text(SAMPLE)
            with self.assertRaisesRegex(testee.OriginalSourceError,"SHA-256"):
                testee.analyze(root)
            with patch.object(testee,"SOURCE_HASH",hashlib.sha256(SAMPLE.encode()).hexdigest()):
                result=testee.analyze(root)
            self.assertTrue(result["functionVerbatimExtracted"])
            for name in ("sourceModified","kernelObjectLinked","oemKernelGuestExecuted",
                         "onDeviceExecuted","rootOrKernelSuProven"):
                self.assertIs(result[name],False)
            self.assertTrue(result["dependenciesMocked"])
            self.assertEqual(len(result["nativeHost"]["observations"]),2)

if __name__=="__main__":unittest.main()
