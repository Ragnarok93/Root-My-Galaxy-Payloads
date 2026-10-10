#!/usr/bin/env python3
"""Unit tests for the read-only HXL1/CVE RT-mutex source audit."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("y2q_rtmutex_fix_audit.py")
spec = importlib.util.spec_from_file_location("y2q_rtmutex_fix_audit", SOURCE)
audit = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(audit)


class FixAuditTests(unittest.TestCase):
    def test_real_published_diff_shapes_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "01-waiter-task-fix.txt"
            first.write_text("""Original RT-mutex fix
diff --git a/kernel/locking/rtmutex.c b/kernel/locking/rtmutex.c
@@ -1,3 +1,4 @@ remove_waiter()
+ struct task_struct *waiter_task = waiter->task;
- raw_spin_lock(&current->pi_lock);
+ raw_spin_lock(&waiter_task->pi_lock);
- current->pi_blocked_on = NULL;
+ waiter_task->pi_blocked_on = NULL;
-                     next_lock, NULL, current);
+                     next_lock, NULL, waiter_task);
""")
            second = root / "02-unenqueued-waiter-fix.txt"
            second.write_text("""RT-mutex follow-up correction
diff --git a/kernel/locking/rtmutex.c b/kernel/locking/rtmutex.c
@@ -1,3 +1,5 @@ remove_waiter()
+ if (!waiter_task) /* never enqueued */
+     return;
diff --git a/kernel/locking/rtmutex_api.c b/kernel/locking/rtmutex_api.c
@@ -1,2 +1,2 @@ rt_mutex_start_proxy_lock
- if (unlikely(ret))
+ if (unlikely(ret < 0))
""")
            self.assertTrue(audit.inspect_reference(first, "ownership")
                            ["allExpectedEditsFound"])
            self.assertTrue(audit.inspect_reference(second, "followup")
                            ["allExpectedEditsFound"])

    def test_missing_correction_remains_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "partial.txt"
            file.write_text(
                "diff --git a/kernel/locking/rtmutex.c b/kernel/locking/rtmutex.c\n"
                "+ remove_waiter();\n+ if (!waiter_task) return;\n"
            )
            result = audit.inspect_reference(file, "followup")
            self.assertFalse(result["allExpectedEditsFound"])
            self.assertFalse(result["diffChecks"]["cleanupNegativeOnlyAdded"])

    def test_source_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "kernel/locking/rtmutex.c"
            source.parent.mkdir(parents=True)
            source.write_text("modified")
            futex = root / "kernel/futex.c"
            futex.write_text("modified")
            with self.assertRaisesRegex(audit.AuditError, "hash mismatch"):
                audit.validate_original(root)

    def test_pin_and_no_phone_modifications(self):
        self.assertEqual(len(audit.SOURCES), 2)
        self.assertEqual(len(audit.REFERENCES), 2)
        script = SOURCE.read_text()
        for forbidden in ("adb push", "adb shell", "fastboot flash",
                          "FUTEX_CMP_REQUEUE_PI", "FUTEX_WAIT_REQUEUE_PI"):
            self.assertNotIn(forbidden, script)
        self.assertIn("runtimeCveReproduced", script)
        self.assertIn("deviceModified", script)

    def test_diff_whitespace_normalization_preserves_change_markers(self):
        self.assertEqual(
            audit.strip_diff_whitespace("+ if (unlikely(ret < 0))"),
            "+if(unlikely(ret<0))"
        )


if __name__ == "__main__":
    unittest.main()
