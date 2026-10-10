#!/usr/bin/env python3
"""Synthetic read-only tests for the exact-HXL1 PREL32 export table audit."""
from __future__ import annotations

from contextlib import redirect_stdout
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

AUDIT_PATH = Path(__file__).resolve().with_name("y2q_export_table_audit.py")
spec = importlib.util.spec_from_file_location("y2q_export_table_audit", AUDIT_PATH)
audit = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(audit)

BASE = 0xFFFFFF8008080000

def fixture(base_path: Path, crc_mode: str = "absent", invalid_gpl_crc: bool = False):
    raw = bytearray(0x4000)
    raw[0x38:0x3C] = b"ARM\x64"
    # One ordinary 8-byte PREL32 export plus one GPL export.
    n_start = BASE + 0x1000
    n_stop = BASE + 0x1008
    g_start = n_stop
    g_stop = BASE + 0x1010
    crc_start = BASE + 0x1100
    crc_stop = crc_start + 4
    gcrc_start = crc_stop
    gcrc_stop = gcrc_start + (8 if invalid_gpl_crc else 4)
    symbols = {
        "_text": BASE,
        "__start___ksymtab": n_start,
        "__stop___ksymtab": n_stop,
        "__start___ksymtab_gpl": g_start,
        "__stop___ksymtab_gpl": g_stop,
        "__start___kcrctab": crc_start,
        "__stop___kcrctab": crc_stop,
        "__start___kcrctab_gpl": gcrc_start,
        "__stop___kcrctab_gpl": gcrc_stop,
        "__ksymtab_commit_creds": n_start,
        "__ksymtab_system_unbound_wq": g_start,
        "commit_creds": BASE + 0x2100,
        "system_unbound_wq": BASE + 0x2200,
    }
    for i, (name, entry_off, value_off, string_off) in enumerate((
        ("commit_creds", 0x1000, 0x2100, 0x1300),
        ("system_unbound_wq", 0x1008, 0x2200, 0x1320),
    )):
        struct.pack_into("<ii", raw, entry_off,
                         value_off - entry_off, string_off - (entry_off + 4))
        data = name.encode() + b"\x00"
        raw[string_off:string_off + len(data)] = data
        if crc_mode == "y":
            # Test a relative CRC pointer, not an inline CRC.
            target_off = 0x1800 + 4 * i
            crc_slot = 0x1100 + 4 * i
            struct.pack_into("<i", raw, crc_slot, target_off - crc_slot)
            struct.pack_into("<I", raw, target_off, 0x12345678 + i)
        else:
            struct.pack_into("<I", raw, 0x1100 + 4 * i, 0x12345678 + i)

    kernel_path = base_path / "kernel.bin"
    kernel_path.write_bytes(raw)
    nm_path = base_path / "kernel.nm"
    nm_path.write_text("".join(
        f"{addr:016x} T {key}\n" for key, addr in sorted(symbols.items())
    ))
    lines = ["CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y", "CONFIG_MODVERSIONS=y",
             "CONFIG_MODULE_SIG_FORCE=y"]
    if crc_mode == "y":
        lines.append("CONFIG_MODULE_REL_CRCS=y")
    elif crc_mode == "n":
        lines.append("# CONFIG_MODULE_REL_CRCS is not set")
    cfg_path = base_path / "config.gz"
    with gzip.open(cfg_path, "wt") as file:
        file.write("\n".join(lines) + "\n")
    return kernel_path, nm_path, cfg_path, hashlib.sha256(raw).hexdigest()

class ExportAuditTests(unittest.TestCase):
    def run_fixture(self, mode="absent", invalid_gpl_crc=False):
        with tempfile.TemporaryDirectory() as td:
            kernel, nm, cfg, sha = fixture(Path(td), mode, invalid_gpl_crc)
            args = ["y2q_export_table_audit.py", "--kernel-bin", str(kernel),
                    "--nm", str(nm), "--config-gz", str(cfg),
                    "--names", "commit_creds", "system_unbound_wq"]
            output = io.StringIO()
            with mock.patch.object(audit, "HXL1_SHA256", sha), \
                 mock.patch.object(sys, "argv", args), \
                 redirect_stdout(output):
                audit.main()
            return json.loads(output.getvalue())

    def test_absent_rel_crc_is_explicitly_provisional(self):
        result = self.run_fixture()
        self.assertEqual(result["normalExports"], 1)
        self.assertEqual(result["normalCrcSlots"], 1)
        self.assertEqual(result["gplExports"], 1)
        self.assertEqual(result["gplCrcSlots"], 1)
        self.assertTrue(all(x["nameMatches"] and x["kallsymsValueMatches"]
                            for x in result["symbols"]))
        for item in result["symbols"]:
            self.assertEqual(item["candidateCrcAssumingAbsolute"],
                             item["crcSlotLittleEndianU32"])
            self.assertNotIn("candidateCrc", item)

    def test_explicitly_disabled_relative_crc(self):
        result = self.run_fixture("n")
        self.assertEqual(result["symbols"][0]["candidateCrc"], "0x12345678")
        self.assertEqual(result["symbols"][1]["candidateCrc"], "0x12345679")

    def test_enabled_relative_crc(self):
        result = self.run_fixture("y")
        self.assertEqual(result["symbols"][0]["candidateCrc"], "0x12345678")
        self.assertEqual(result["symbols"][1]["candidateCrc"], "0x12345679")
        self.assertIn("relativeCrcTargetVA", result["symbols"][0])

    def test_invalid_gpl_crc_count_rejected(self):
        with self.assertRaisesRegex(ValueError, "GPL export count"):
            self.run_fixture(invalid_gpl_crc=True)

    def test_missing_config_option_is_not_explicit_n(self):
        self.assertEqual(audit.config_option("CONFIG_MODVERSIONS=y",
                                            "CONFIG_MODULE_REL_CRCS"), "absent")
        self.assertEqual(audit.config_option("# CONFIG_MODULE_REL_CRCS is not set",
                                            "CONFIG_MODULE_REL_CRCS"), "n")

if __name__ == "__main__":
    unittest.main()
