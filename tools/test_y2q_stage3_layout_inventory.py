#!/usr/bin/env python3
"""Test read-only HXL1 stage-three provenance inventory."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("y2q_stage3_layout_inventory.py")
spec = importlib.util.spec_from_file_location("y2q_stage3_layout_inventory", SCRIPT)
inv = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(inv)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Stage3Tests(unittest.TestCase):
    def fixture(self, td):
        root = Path(td)
        stock = root / "artifacts"
        source = root / "vendor"
        (stock / "hxl1-research").mkdir(parents=True)
        (source / "kernel/locking").mkdir(parents=True)
        (source / "include/linux").mkdir(parents=True)
        original = {
            "kernel.bin": b"stock-image",
            "config.gz": gzip.compress(
                b"CONFIG_DEBUG_INFO=y\n# CONFIG_DEBUG_INFO_BTF is not set\n"
                b"CONFIG_ARM64=y\n"
            ),
        }
        vendor = {"kernel/locking/rtmutex.c": b"static int removed(void) {}\n",
                  "kernel/futex.c": b"/* stock source */\n"}
        for name, data in original.items():
            (stock / name).write_bytes(data)
        for rel, data in vendor.items():
            (source / rel).write_bytes(data)
        (source / "include/linux/sched.h").write_text(
            "struct task_struct {\n int foo;\n};\n")
        return stock, source, {k: sha(v) for k, v in original.items()}, {
            k: sha(v) for k, v in vendor.items()
        }

    def test_hash_and_config_inventory_preserves_partial_stage(self):
        with tempfile.TemporaryDirectory() as td:
            stock, source, originals, vendor = self.fixture(td)
            with mock.patch.object(inv, "PINNED", originals), \
                 mock.patch.object(inv, "SOURCE_PINNED", vendor):
                result = inv.make_inventory(source, stock)
            self.assertTrue(result["originalFileHashChecksPassed"])
            self.assertEqual(result["sourceConfig"]["CONFIG_DEBUG_INFO"], "y")
            self.assertEqual(result["sourceConfig"]["CONFIG_DEBUG_INFO_BTF"], "n")
            self.assertEqual(
                result["sourceDeclarations"]["task_struct"]["definitions"][0]["line"],
                1)
            self.assertFalse(result["offsetsVerified"])
            self.assertFalse(result["root"])
            self.assertIn("Gate remains open", inv.as_markdown(result))

    def test_original_hash_mismatch_fails_before_audit(self):
        with tempfile.TemporaryDirectory() as td:
            stock, source, originals, vendor = self.fixture(td)
            (stock / "kernel.bin").write_bytes(b"tampered")
            with mock.patch.object(inv, "PINNED", originals), \
                 mock.patch.object(inv, "SOURCE_PINNED", vendor):
                with self.assertRaisesRegex(inv.InventoryError, "mismatch"):
                    inv.make_inventory(source, stock)

    def test_invalid_reconstructed_elf_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            elf = Path(td) / "vmlinux-stock.elf"
            self.assertEqual(inv.sections(elf)["state"], "MISSING")
            elf.write_bytes(b"not an ELF")
            with self.assertRaisesRegex(inv.InventoryError, "not ELF64"):
                inv.sections(elf)

    def test_synthetic_elf_dwarf_section_detected(self):
        with tempfile.TemporaryDirectory() as td:
            elf = Path(td) / "test.elf"
            names = b"\x00.shstrtab\x00.debug_info\x00"
            data = bytearray(64 + 3 * 64 + len(names))
            data[0:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", data, 18, 183)
            struct.pack_into("<Q", data, 40, 64)
            struct.pack_into("<HHH", data, 58, 64, 3, 1)
            strtab = 64 + 3 * 64
            struct.pack_into("<I", data, 64 + 64, 1)
            struct.pack_into("<Q", data, 64 + 64 + 24, strtab)
            struct.pack_into("<Q", data, 64 + 64 + 32, len(names))
            struct.pack_into("<I", data, 64 + 2 * 64, 11)
            data[strtab:] = names
            elf.write_bytes(data)
            report = inv.sections(elf)
            self.assertEqual(report["state"], "SECTIONS_FOUND")
            self.assertEqual(report["debug"], [".debug_info"])
            self.assertFalse(report["btf"])

    def test_source_locations_are_not_claimed_offsets(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)
            path = source / "include/linux/sched.h"
            path.parent.mkdir(parents=True)
            path.write_text(
                "struct task_struct;\n"
                "struct task_struct {\n long x;\n};\n")
            data = inv.declarations(source)
            self.assertEqual(data["task_struct"]["definitions"][0]["line"], 2)
            self.assertFalse(data["task_struct"]["verifiedOffsets"])
            self.assertEqual(data["page"]["definitions"], [])

    def test_no_physical_or_privilege_actions(self):
        code = SCRIPT.read_text()
        for forbidden in ("adb shell", "adb push", "fastboot flash",
                          "FUTEX_CMP_REQUEUE_PI", "FUTEX_WAIT_REQUEUE_PI",
                          "init_module(", "setresuid(0)"):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
