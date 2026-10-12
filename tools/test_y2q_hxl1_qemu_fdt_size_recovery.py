"""Offline host tests for HXL1 early ARM64 FDT <=2MiB recovery guard."""
from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from tools import y2q_hxl1_qemu_fdt_size_recovery as r
from tools import y2q_hxl1_qemu_virt_dtb_inventory as fdt
from tools.test_y2q_hxl1_qemu_virt_dtb_inventory import make_dtb

def original():
    b=bytearray(make_dtb(reserve=(),reserved=False))
    size=1048576
    struct.pack_into(">I",b,4,size)
    b.extend(bytes(size-len(b)))
    return bytes(b)

class FdtSizeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.original=original()

    def test_compact_preserves_fdt_structures_and_memory(self):
        smaller,record=r.compact_source(self.original,strict_pin=False)
        self.assertLess(len(smaller),len(self.original))
        self.assertGreater(record["removedVerifiedZeroPaddingBytes"],0)
        a=fdt.parse_fdt(self.original)
        b=fdt.parse_fdt(smaller)
        self.assertEqual(a["memoryRanges"],b["memoryRanges"])
        self.assertEqual(a["nodeCount"],b["nodeCount"])
        self.assertEqual(a["chosenInitrd"],b["chosenInitrd"])
        self.assertEqual(b["memoryReservationEntries"],[])
        self.assertTrue(record["originalStructureBytesPreserved"])

    def test_diagnostic_override_has_exact_one_fdt_reservation(self):
        compact,manifest=r.build_recovery(self.original,strict_pin=False)
        parsed=fdt.parse_fdt(compact)
        self.assertLess(len(compact),r.ARM64_LIMIT)
        self.assertEqual(parsed["memoryReservationEntries"],[{
            "start":"0x48000000","endExclusive":"0x48200000",
            "sizeBytes":2097152}])
        self.assertFalse(manifest["qemuGuestRuntimeFdtSizeVerified"])
        self.assertFalse(manifest["secureRkpPoolReserved"])

    def test_original_guest_size_exceeds_two_megabytes(self):
        self.assertEqual(r.OWNER_V3_GUEST_BYTES,2117184)
        self.assertEqual(r.ARM64_LIMIT,2097152)
        self.assertEqual(r.OWNER_V3_GUEST_BYTES-r.ARM64_LIMIT,20032)

    def test_exact_reconstruction_detects_artifact_tamper(self):
        compact,manifest=r.build_recovery(self.original,strict_pin=False)
        self.assertEqual(r.verify_recovery(
            self.original,compact,manifest,strict_pin=False),manifest)
        changed=copy.deepcopy(manifest)
        changed["overrideSha256"]="00"*32
        with self.assertRaisesRegex(r.RecoveryError,"Manifest"):
            r.verify_recovery(self.original,compact,changed,strict_pin=False)
        bad=bytearray(compact)
        bad[-1]^=1
        with self.assertRaisesRegex(r.RecoveryError,"differs"):
            r.verify_recovery(self.original,bytes(bad),manifest,strict_pin=False)

    def test_nonzero_trailing_bytes_cannot_be_discarded(self):
        b=bytearray(self.original)
        b[-1]=1
        with self.assertRaisesRegex(r.RecoveryError,"nonzero"):
            r.compact_source(bytes(b),strict_pin=False)

    def test_original_source_hash_mismatch_rejected(self):
        with self.assertRaisesRegex(r.RecoveryError,"hash mismatch"):
            r.compact_source(self.original,strict_pin=True)

    def test_non_original_ram_profile_rejected(self):
        bad=make_dtb(reserve=(),reserved=False,memory=(0x80000000,0x40000000))
        with self.assertRaisesRegex(r.RecoveryError,"known unreserved"):
            r.compact_source(bad,strict_pin=False)

    def test_already_reserved_original_fails_closed(self):
        bad=make_dtb(reserved=True,reserve=())
        with self.assertRaisesRegex(r.RecoveryError,"known unreserved"):
            r.compact_source(bad,strict_pin=False)

    def test_missing_structure_section_rejected(self):
        b=bytearray(self.original)
        struct.pack_into(">I",b,8,0xffffffff)
        with self.assertRaises((r.RecoveryError,fdt.FdtError)):
            r.compact_source(bytes(b),strict_pin=False)

    def test_no_source_slack_reports_inconclusive(self):
        src,_=r.compact_source(self.original,strict_pin=False)
        with self.assertRaisesRegex(r.RecoveryError,"No removable trailing padding"):
            r.build_recovery(src,strict_pin=False)

    def test_cli_invocation_isolated(self):
        with tempfile.TemporaryDirectory() as d:
            cmd=[sys.executable,"-I",str(Path(r.__file__)),"--help"]
            result=subprocess.run(cmd,cwd=d,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("--verify-dir",result.stdout)

    def test_recovery_does_not_call_qemu_or_phone(self):
        text=Path(r.__file__).read_text()
        for token in ("qemu-system-aarch64", "fastboot flash",
                      "adb shell","cpu_physical_memory_write","root@"):
            self.assertNotIn(token,text)
        self.assertIn("verify_recovery",text)

if __name__=="__main__":
    unittest.main()
