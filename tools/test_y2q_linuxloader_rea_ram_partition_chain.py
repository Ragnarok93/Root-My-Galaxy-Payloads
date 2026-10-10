#!/usr/bin/env python3
"""Offline tests for authenticated RAM-partition caller-to-reader evidence."""
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest

from tools import y2q_linuxloader_rea_ram_partition_chain as ram
from tools.y2q_linuxloader_rea_stage4_xrefs import AuditError


def source_fixture():
    return {
        "loaderSha256": ram.LOADER_SHA256,
        "functions": [
            {"label": "base-memory-provider", "status": "VERIFIED_STATIC_FUNCTION",
             "functionEntry": "0x1f018", "evidenceId": "ev-base",
             "highFunctionAvailable": True,
             "pseudocode":
                "FUN_0001eca0(&local_30,&local_34);\n"
                "*param_1 = uVar5;\n"
                'FUN_log("Memory Base Address: 0x%x",*param_1);\n'},
            {"label": "kaslr-initializer", "status": "VERIFIED_STATIC_FUNCTION",
             "functionEntry": "0x20838", "evidenceId": "ev-rng",
             "pseudocode": "UEFI PRNG protocol"},
            {"label": "exit-boot-services", "status": "VERIFIED_STATIC_FUNCTION",
             "functionEntry": "0x1e868", "evidenceId": "ev-exit",
             "pseudocode": "GetMemoryMap and ExitBootServices"},
            {"label": "ram-partition-reader", "status": "VERIFIED_STATIC_FUNCTION",
             "functionEntry": "0x1eca0", "evidenceId": "ev-ram",
             "highFunctionAvailable": True,
             "pseudocode": "ReadRamPartitions(void) {\n"
                           "FUN_00020ff0(&DAT_00123456);\n"
                           "return 0;\n}\n"},
        ],
    }


class RamPartitionProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def analyze(self, value=None):
        with patch.object(ram, "source_audit", return_value=value or source_fixture()):
            return ram.analyze(self.directory)

    def test_verifies_direct_original_call_and_maintains_unknown(self):
        result = self.analyze()
        self.assertEqual(result["baseProviderEntry"], "0x1f018")
        self.assertEqual(result["partitionReaderEntry"], "0x1eca0")
        self.assertEqual(result["readerEvidenceId"], "ev-ram")
        self.assertFalse(result["physicalRamBaseMeasured"])
        self.assertFalse(result["kernelPhysicalEntryVerified"])
        self.assertFalse(result["deviceModified"])

    def test_reader_pseudocode_preserved_full(self):
        result = self.analyze()
        self.assertIn("FUN_00020ff0", result["readerFunctionPseudocode"])
        self.assertIn("FUN_00020ff0", ram.render(result))

    def test_original_sha_mismatch_refused(self):
        broken = source_fixture()
        broken["loaderSha256"] = "0"*64
        with self.assertRaisesRegex(AuditError, "digest"):
            self.analyze(broken)

    def test_no_verified_reader_refused(self):
        broken = source_fixture()
        broken["functions"][3]["status"] = "FUNCTION_NOT_VERIFIED"
        with self.assertRaisesRegex(AuditError, "Four genuine"):
            self.analyze(broken)

    def test_no_assumed_min_without_original_call(self):
        broken = source_fixture()
        broken["functions"][0]["pseudocode"] = "*param_1 = 0x80000000;"
        with self.assertRaisesRegex(AuditError, "Cannot authenticate"):
            self.analyze(broken)

    def test_wrong_reader_entry_refused(self):
        broken = source_fixture()
        broken["functions"][3]["functionEntry"] = "0xdead"
        with self.assertRaisesRegex(AuditError, "entry mismatch"):
            self.analyze(broken)

    def test_no_empty_or_oversize_code_promoted(self):
        for code in ("", " " * 100, "A" * (ram.MAX_READER_CHARS + 1)):
            with self.subTest(length=len(code)):
                broken = source_fixture()
                broken["functions"][3]["pseudocode"] = code
                with self.assertRaisesRegex(AuditError, "absent or oversized"):
                    self.analyze(broken)


if __name__ == "__main__":
    unittest.main()
