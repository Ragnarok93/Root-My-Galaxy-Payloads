#!/usr/bin/env python3
"""Host-only tests for the Galaxy S20+ WSL2 diagnostic orchestrator."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr

MODULE = Path(__file__).resolve().with_name("run_y2q_futex_smoke.py")
spec = importlib.util.spec_from_file_location("run_y2q_futex_smoke", MODULE)
runner = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(runner)


def dummy_arm64_executable(path: Path, *, e_type: int = 3,
                           machine: int = 183) -> None:
    header = bytearray(128)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", header, 16, e_type, machine)
    path.write_bytes(header)


def command_result(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(["mock"], returncode, stdout, stderr)


class TestWslFutexRunner(unittest.TestCase):

    def test_arm64_pie_validation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "futex-pi"
            dummy_arm64_executable(path)
            digest = runner.require_arm64_android_elf(path)
            self.assertEqual(len(digest), 64)
            dummy_arm64_executable(path, machine=62)
            with self.assertRaisesRegex(runner.DiagnosticError, "AArch64"):
                runner.require_arm64_android_elf(path)
            path.write_bytes(b"not an elf")
            with self.assertRaises(runner.DiagnosticError):
                runner.require_arm64_android_elf(path)

    def test_multiple_adb_devices_require_explicit_serial(self):
        two_devices = command_result(
            "List of devices attached\nAAA\tdevice\nBBB\tdevice\n")
        with mock.patch.object(runner, "command", return_value=two_devices):
            with self.assertRaisesRegex(runner.DiagnosticError, "exactly one"):
                runner.connected_device("adb", None)
            self.assertEqual(runner.connected_device("adb", "AAA"), "AAA")
            with self.assertRaisesRegex(runner.DiagnosticError, "not an online"):
                runner.connected_device("adb", "CCC")

    def test_preflight_fails_closed_on_wrong_model(self):
        def fake_command(args, **kwargs):
            if args[-2:] == ["getprop", "ro.product.model"]:
                return command_result("SM-G988U1\n")
            return command_result("unknown\n")
        with mock.patch.object(runner, "command", side_effect=fake_command):
            with self.assertRaisesRegex(runner.DiagnosticError, "ro.product.model"):
                runner.verify_device("adb", "testserial")

    def test_preflight_checks_all_exact_expected_values(self):
        def fake_command(args, **kwargs):
            if "getprop" in args:
                return command_result(
                    runner.EXPECTED[args[-1]] + "\n")
            mapping = {
                ("uname", "-r"): runner.EXPECTED_KERNEL,
                ("getconf", "PAGESIZE"): runner.EXPECTED_PAGE_SIZE,
                ("id", "-u"): "2000",
                ("getenforce",): "Enforcing",
            }
            return command_result(mapping[tuple(args[4:])] + "\n")
        with mock.patch.object(runner, "command", side_effect=fake_command):
            observed = runner.verify_device("adb", "testserial")
        self.assertEqual(observed["SELinux enforcement"], "Enforcing")
        self.assertEqual(observed["ro.boot.bootloader"],
                         "G986U1UESCHXL1")

    def test_preflight_only_never_pushes_or_runs_binary(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / "futex-pi"
            dummy_arm64_executable(binary)
            argv = [
                "run_y2q_futex_smoke.py", "--binary", str(binary),
                "--output-dir", str(Path(td) / "reports"),
                "--preflight-only"
            ]
            output = io.StringIO()
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(runner, "connected_device",
                                   return_value="serial"), \
                 mock.patch.object(runner, "verify_device",
                                   return_value={"uid": "2000"}), \
                 redirect_stdout(output):
                self.assertEqual(runner.main(), 0)
            reports = list((Path(td) / "reports").glob("*.json"))
            self.assertEqual(len(reports), 1)
            result = json.loads(reports[0].read_text())
            self.assertEqual(result["status"], "PREFLIGHT_ONLY")
            self.assertNotIn("exitCode", result)

    def test_device_cleanup_on_success_and_failure(self):
        for success in (True, False):
            with self.subTest(success=success), tempfile.TemporaryDirectory() as td:
                binary = Path(td) / "futex-pi"
                dummy_arm64_executable(binary)
                argv = [
                    "run_y2q_futex_smoke.py", "--binary", str(binary),
                    "--output-dir", str(Path(td) / "reports")
                ]
                called = []
                expected_status = ("PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY"
                                   if success else "FAIL_PI_SEMANTICS")

                def fake_command(args, **kwargs):
                    called.append(list(args))
                    if args[-3:-1] == ["test", "-e"]:
                        return command_result(returncode=1)
                    if len(args) == 5 and args[3] == "shell" \
                            and args[4].startswith("/data/local/tmp/"):
                        return command_result(
                            f"RESULT={expected_status}\r\n",
                            returncode=0 if success else 4
                        )
                    return command_result()

                with mock.patch.object(sys, "argv", argv), \
                     mock.patch.object(runner, "connected_device",
                                       return_value="serial"), \
                     mock.patch.object(runner, "verify_device",
                                       return_value={"uid": "2000"}), \
                     mock.patch.object(runner, "command",
                                       side_effect=fake_command), \
                     redirect_stdout(io.StringIO()), \
                     redirect_stderr(io.StringIO()):
                    self.assertEqual(runner.main(), 0 if success else 3)
                self.assertTrue(any(x[3:5] == ["shell", "rm"]
                                    for x in called))
                reports = list((Path(td) / "reports").glob("*.json"))
                self.assertEqual(len(reports), 1)
                self.assertEqual(json.loads(reports[0].read_text())["status"],
                                 expected_status)

    def test_no_root_or_device_setting_mutation_commands_in_runner(self):
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in (
            '["su"', '["setenforce"', '["insmod"', '["finit_module"',
            '["mount"', '["sysctl"', '["fastboot"', '["reboot"'
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
