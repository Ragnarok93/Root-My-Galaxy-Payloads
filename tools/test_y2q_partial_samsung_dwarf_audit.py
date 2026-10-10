#!/usr/bin/env python3
"""Regression tests for the HXL1 Clang18 partial-object read-only audit."""
from __future__ import annotations
import gzip
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("y2q_partial_samsung_dwarf_audit.py")
spec = importlib.util.spec_from_file_location("y2q_partial_samsung_dwarf_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(audit)

def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def fake_arm64_debug_object() -> bytes:
    strings = b"\0.shstrtab\0.debug_info\0.debug_abbrev\0.symtab\0"
    size = 64 + 5 * 64 + len(strings)
    body = bytearray(size)
    body[0:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", body, 16, 1, 183)
    struct.pack_into("<Q", body, 40, 64)
    struct.pack_into("<HHH", body, 58, 64, 5, 1)
    start = 64 + 5 * 64
    struct.pack_into("<I", body, 64 + 64, 1)
    struct.pack_into("<Q", body, 64 + 64 + 24, start)
    struct.pack_into("<Q", body, 64 + 64 + 32, len(strings))
    for i, off in enumerate((11, 23, 37), 2):
        struct.pack_into("<I", body, 64 + i * 64, off)
    body[start:] = strings
    return bytes(body)

class DwarfAuditTests(unittest.TestCase):
    def test_arm64_object_detects_real_section_names(self):
        with tempfile.TemporaryDirectory() as td:
            obj = Path(td) / "main.o"
            obj.write_bytes(fake_arm64_debug_object())
            r = audit.arm64_object(obj)
            self.assertEqual(r["kind"], "ARM64_REL")
            self.assertTrue(r["hasDwarf"])
            self.assertTrue(r["hasSymtab"])
            self.assertIn(".debug_info", r["debugSections"])

    def test_non_arm64_object_cannot_count_as_samsung_dwarf(self):
        with tempfile.TemporaryDirectory() as td:
            obj = Path(td) / "host.o"
            b = bytearray(fake_arm64_debug_object())
            struct.pack_into("<H", b, 18, 62)
            obj.write_bytes(b)
            self.assertEqual(audit.arm64_object(obj)["kind"], "NOT_ARM64_REL")

    def test_malformed_section_table_does_not_pass(self):
        with tempfile.TemporaryDirectory() as td:
            obj = Path(td) / "broken.o"
            b = bytearray(fake_arm64_debug_object())
            struct.pack_into("<Q", b, 40, 0xFFFFFFFFFFFFFF00)
            obj.write_bytes(b)
            self.assertEqual(audit.arm64_object(obj)["kind"], "MALFORMED_SECTIONS")

    def test_compiler_config_difference_remains_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            generated = root / ".config"
            stock = root / "config.gz"
            generated.write_text("CONFIG_CLANG_VERSION=180103\nCONFIG_ARM64=y\n")
            stock.write_bytes(gzip.compress(
                b"CONFIG_CLANG_VERSION=100006\nCONFIG_ARM64=y\n"))
            r = audit.compare_config(generated, stock)
            self.assertFalse(r["compilerVersionMatches"])
            self.assertEqual(r["commonMatching"], 1)
            self.assertEqual(r["commonDifferences"]["CONFIG_CLANG_VERSION"]["stock"], "100006")

    def test_hash_pins_and_selected_objects(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            build, source, stock = root / "build", root / "source", root / "stock"
            build.mkdir()
            source.mkdir()
            stock.mkdir()
            generated = b"CONFIG_CLANG_VERSION=180103\n"
            original = gzip.compress(b"CONFIG_CLANG_VERSION=100006\n")
            (build / ".config").write_bytes(generated)
            (stock / "config.gz").write_bytes(original)
            source_pins = {}
            for relative in audit.SOURCE_PINS:
                file = source / relative
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(relative.encode())
                source_pins[relative] = hash_bytes(relative.encode())
            obj = build / "init/main.o"
            obj.parent.mkdir()
            obj.write_bytes(fake_arm64_debug_object())
            with (mock.patch.object(audit, "GENERATED_SHA", hash_bytes(generated)),
                  mock.patch.object(audit, "STOCK_CONFIG_SHA", hash_bytes(original)),
                  mock.patch.object(audit, "SOURCE_PINS", source_pins)):
                result = audit.audit(build, source, stock)
            self.assertEqual(result["objectCount"], 1)
            self.assertEqual(result["arm64DwarfCount"], 1)
            self.assertEqual(result["selected"]["init/main.o"]["kind"], "ARM64_REL")
            self.assertFalse(result["factoryAbiVerified"])
            self.assertFalse(result["actualRootPayloadAvailable"])
            self.assertIn("Clang18", audit.to_markdown(result))

    def test_mismatched_build_config_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / ".config"
            file.write_bytes(b"wrong config")
            with self.assertRaisesRegex(audit.AuditError, "SHA256"):
                audit.pin(file, "0" * 64)

    def test_no_phone_or_kernel_write_paths(self):
        source = SCRIPT.read_text()
        for forbidden in ("adb shell", "adb push", "fastboot flash",
                          "FUTEX_CMP_REQUEUE_PI", "FUTEX_WAIT_REQUEUE_PI",
                          "init_module(", "sudo make", "setresuid(0)"):
            self.assertNotIn(forbidden, source)
        self.assertIn('"factoryAbiVerified": False', source)
        self.assertIn('"phoneTouched": False', source)

if __name__ == "__main__":
    unittest.main()
