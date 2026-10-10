#!/usr/bin/env python3
"""Offline tests for original HXL1 Qualcomm EFI RAM-partition GUID analysis."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_ram_partition_protocol_audit as impl
from tools.y2q_linuxloader_rea_stage4_xrefs import AuditError


def chain():
    return {
        "loaderSha256": impl.LOADER_SHA256,
        "partitionReaderEntry": "0x1eca0",
        "baseProviderEntry": "0x1f018",
        "readerEvidenceId": "ev-reader",
        "readerFunctionPseudocode":
            "DAT_000ef880; DAT_00351a38 + 0x140; "
            "local_50 + 0x18; DAT_00346ae0 << 4",
        "callerFunctionPseudocode":
            "FUN_0001eca0(&local_30,&local_34); puVar8 + 2;",
    }


class OriginalRamAbiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.rec = {
            "operation": "read_bytes",
            "provider": {"id": "ghidra"},
            "subject": {"digest": {"sha256": impl.LOADER_SHA256},
                        "architecture": "arm64"},
            "parameters": {"address": "0xef880", "length": 16},
            "normalized_result": {
                "address": "0xef880",
                "requested_bytes": 16,
                "returned_bytes": 16,
                "complete": True,
                "bytes_hex": impl.GUID_HEX,
            },
            "evidence_id": "ev-guid",
        }
        self.write()

    def write(self):
        (self.folder/impl.READ_FILE).write_text(json.dumps(self.rec))

    def evaluate(self, source=None):
        with patch.object(impl, "verify_call_chain", return_value=source if source is not None else chain()):
            return impl.audit(self.folder)

    def test_known_guid_and_binary_layout(self):
        data=self.evaluate()
        self.assertEqual(data["protocolGuid"], impl.GUID_TEXT)
        self.assertEqual(data["recordSize"], 16)
        self.assertEqual(data["fieldOffsets"], {"Base":0, "AvailableLength":8})
        self.assertEqual(data["protocolMethodOffset"], 0x18)
        self.assertFalse(data["physicalBaseMeasured"])
        self.assertFalse(data["deviceModified"])

    def test_writes_no_live_physical_address(self):
        report=self.evaluate()
        text=impl.markdown(report)
        self.assertIn("UNVERIFIED",text)
        self.assertFalse(report["kernelPhysicalEntryVerified"])

    def test_guid_is_little_endian_efi_encoding(self):
        result=impl.guid_observation(self.folder)
        self.assertEqual(result["guid"],impl.GUID_TEXT)
        self.assertEqual(result["hex"],impl.GUID_HEX)

    def test_wrong_original_subject_refused(self):
        self.rec["subject"]["digest"]["sha256"]="0"*64
        self.write()
        with self.assertRaisesRegex(AuditError,"authenticated original"):
            self.evaluate()

    def test_guid_mismatch_refused_not_silently_accepted(self):
        self.rec["normalized_result"]["bytes_hex"]="00"*16
        self.write()
        with self.assertRaisesRegex(AuditError,"differs"):
            self.evaluate()

    def test_incomplete_guid_read_refused(self):
        self.rec["normalized_result"]["complete"]=False
        self.write()
        with self.assertRaisesRegex(AuditError,"incomplete"):
            self.evaluate()

    def test_wrong_static_guid_query_refused(self):
        self.rec["parameters"]["address"]="0x123456"
        self.write()
        with self.assertRaisesRegex(AuditError,"authenticated original"):
            self.evaluate()

    def test_caller_stride_not_inferred_when_missing(self):
        source=chain()
        source["callerFunctionPseudocode"]="FUN_0001eca0(&local_30,&local_34)"
        with self.assertRaisesRegex(AuditError,"16-byte stride"):
            self.evaluate(source)

    def test_protocol_dispatch_not_inferred_when_missing(self):
        source=chain()
        source["readerFunctionPseudocode"]="DAT_000ef880"
        with self.assertRaisesRegex(AuditError,"dispatch"):
            self.evaluate(source)

    def test_wrong_reader_identity_refused(self):
        source=chain()
        source["partitionReaderEntry"]="0xdead"
        with self.assertRaisesRegex(AuditError,"not verified"):
            self.evaluate(source)


if __name__=="__main__":
    unittest.main()
