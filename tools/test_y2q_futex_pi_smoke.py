#!/usr/bin/env python3
"""Build/host-test the benign ARM64 HXL1 futex-PI smoke diagnostic.

Host compilation uses explicit RMG_HOST_TEST for CI only; production Android
compilation deliberately has no bypass for device/firmware/ADB shell identity.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "research/y2q-G986U1UESCHXL1/futex_pi_smoke.c"
BUILD_SCRIPT = ROOT / "research/y2q-G986U1UESCHXL1/build_futex_pi_smoke.sh"

class FutexPiSmokeTests(unittest.TestCase):
    def test_risk_bounding_and_android_identity_guard(self):
        source = SOURCE.read_text(encoding="utf-8")
        script = BUILD_SCRIPT.read_text(encoding="utf-8")
        for expected in (
            "FUTEX_WAIT_PRIVATE", "FUTEX_WAKE_PRIVATE",
            "FUTEX_LOCK_PI_PRIVATE", "FUTEX_TRYLOCK_PI_PRIVATE",
            "FUTEX_UNLOCK_PI_PRIVATE", "RMG_HOST_TEST",
            "getuid() != 2000", "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state", "EXPECTED_FIRMWARE",
            "EXPECTED_FINGERPRINT", "RESULT=PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY"
        ):
            self.assertIn(expected, source)
        for forbidden in (
            "FUTEX_WAIT_REQUEUE_PI", "FUTEX_CMP_REQUEUE_PI",
            "FUTEX_REQUEUE_PRIVATE", "FUTEX_CMP_REQUEUE_PRIVATE",
            "pthread_create(", "clone(", "fork(", "execve(",
            "init_module(", "finit_module(", "ptrace(", "mprotect(",
            "setuid(", "setresuid(", "CAP_SYS_ADMIN"
        ):
            # The source comment may name a class, but must never call it.
            if forbidden in ("FUTEX_WAIT_REQUEUE_PI", "FUTEX_CMP_REQUEUE_PI"):
                self.assertNotIn(forbidden, source)
            else:
                self.assertNotIn(forbidden, source)
        self.assertIn("aarch64-linux-android33-clang", script)
        self.assertNotIn("RMG_HOST_TEST", script)

    @unittest.skipUnless(shutil.which("cc"), "Host C compiler unavailable")
    def test_host_compile_and_uncontended_smoke(self):
        with tempfile.TemporaryDirectory() as td:
            binary = pathlib.Path(td) / "futex-pi-host-only"
            subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-D_GNU_SOURCE", "-DRMG_HOST_TEST", str(SOURCE), "-o", str(binary)],
                check=True, capture_output=True, text=True, timeout=30,
            )
            info = subprocess.run(
                [str(binary), "--describe"],
                capture_output=True, text=True, check=True, timeout=5,
            )
            self.assertIn("SAFE FUTEX PI SMOKE V1", info.stdout)
            self.assertIn("NO=threads,contention,requeue", info.stdout)

            result = subprocess.run(
                [str(binary)], capture_output=True, text=True, timeout=5,
            )
            self.assertIn(result.returncode, (0, 3),
                          f"Unexpected host futex failure: {result.stdout}\n{result.stderr}")
            self.assertIn("IDENTITY=HOST_TEST_ONLY", result.stdout)
            self.assertIn("CHECK=WAIT_VALUE_MISMATCH STATUS=PASS", result.stdout)
            self.assertIn("CHECK=WAKE_NO_WAITERS STATUS=PASS", result.stdout)
            self.assertIn("CHECK=LOCK_PI_UNCONTENDED STATUS=", result.stdout)
            self.assertIn("CHECK=TRYLOCK_PI_UNCONTENDED STATUS=", result.stdout)
            if result.returncode == 0:
                self.assertIn("RESULT=PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY", result.stdout)
            else:
                self.assertIn("RESULT=INCONCLUSIVE_PI_UNAVAILABLE", result.stdout)

    @unittest.skipUnless(shutil.which("cc"), "Host C compiler unavailable")
    def test_accidental_host_distribution_compile_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(SOURCE), "-o", str(pathlib.Path(td) / "should-not-build")],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("Device binary must target AArch64", p.stderr)

if __name__ == "__main__":
    unittest.main()
