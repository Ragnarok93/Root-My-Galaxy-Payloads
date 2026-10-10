#!/usr/bin/env python3
"""Tests for fail-closed pahole DWARF type presence detection."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("y2q_dwarf_type_presence.py")
spec = importlib.util.spec_from_file_location("y2q_dwarf_type_presence", SCRIPT)
tool = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(tool)


class PresenceTests(unittest.TestCase):
    def test_pahole_zero_exit_but_missing_type_not_present(self):
        self.assertEqual(
            tool.classify("", "pahole: type 'rt_mutex_waiter' not found", 0,
                          "rt_mutex_waiter"), "NOT_FOUND")

    def test_complete_struct_must_be_printed(self):
        s = "struct rt_mutex_waiter {\n  int test; /* 0 4 */\n};\n"
        self.assertEqual(
            tool.classify(s, "", 0, "rt_mutex_waiter"), "PRESENT")
        self.assertEqual(
            tool.classify(s, "", 1, "rt_mutex_waiter"), "INCONSISTENT_TOOL_STATUS")

    def test_other_type_is_not_accepted(self):
        printed = "struct rt_mutex_waiter {\n long x;\n};\n"
        self.assertEqual(tool.classify(printed, "", 0, "rt_mutex"),
                         "NO_COMPLETE_DEFINITION")

    def test_forward_declaration_is_not_complete(self):
        self.assertEqual(tool.classify("struct rt_mutex;\n", "", 0, "rt_mutex"),
                         "NO_COMPLETE_DEFINITION")

    def test_tool_errors_are_not_accepted_as_present(self):
        self.assertEqual(tool.classify("", "no DWARF", 1, "rt_mutex"),
                         "TOOL_ERROR")

    def test_probe_considers_output_not_only_exit_code(self):
        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = "pahole: type 'rt_mutex' not found"
        with mock.patch.object(tool.subprocess, "run", return_value=FakeResult()):
            got = tool.probe(Path("/tmp/example.o"), "rt_mutex")
        self.assertEqual(got["status"], "NOT_FOUND")
        self.assertEqual(got["returnCode"], 0)

    def test_invalid_names_rejected(self):
        with self.assertRaises(ValueError):
            tool.classify("", "", 0, "rt_mutex; exit")

    def test_arm64_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.o"
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<HH", data, 16, 1, 183)
            path.write_bytes(data)
            self.assertTrue(tool.arch_object(path))
            struct.pack_into("<H", data, 18, 62)
            path.write_bytes(data)
            self.assertFalse(tool.arch_object(path))

    def test_pinned_build_config_guard(self):
        with tempfile.TemporaryDirectory() as td:
            build = Path(td)
            (build / ".config").write_text("CONFIG_CLANG_VERSION=180103\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                tool.run(build)

    def test_no_offset_or_privilege_outputs(self):
        source = SCRIPT.read_text()
        for forbidden in ("adb shell", "adb push", "fastboot flash",
                          "FUTEX_CMP_REQUEUE_PI", "init_module(", "setresuid(0)"):
            self.assertNotIn(forbidden, source)
        self.assertIn('"stockFirmwareLayoutVerified": False', source)
        self.assertIn('"rootVerified": False', source)


if __name__ == "__main__":
    unittest.main()
