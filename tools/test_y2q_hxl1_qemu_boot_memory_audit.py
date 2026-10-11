"""Offline original HXL1 kernel + generated QEMU DTB conflict audit tests."""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import y2q_hxl1_qemu_boot_memory_audit as m
from tools import y2q_hxl1_qemu_virt_dtb_inventory as d
from tools.test_y2q_hxl1_qemu_virt_dtb_inventory import make_dtb


def metadata(size=0x100000, image_size=0x180000):
    return {
        "sha256":m.image_probe.STOCK_SHA256,
        "size":size,
        "imageSize":hex(image_size),
        "textOffset":"0x80000"
    }


class MemoryConflictAuditTests(unittest.TestCase):
    def setUp(self):
        self.blob=make_dtb()
        self.dtb=d.parse_fdt(self.blob)

    def test_snapshot_fdt_and_inventory_are_consistent(self):
        self.assertEqual(m.validate_fdt(self.blob,self.dtb),self.dtb)

    def test_original_dtb_hash_mismatch_rejected(self):
        altered=copy.deepcopy(self.dtb)
        altered["qemuGeneratedFdtSha256"]="00"*32
        with self.assertRaisesRegex(m.AuditError,"hash"):
            m.validate_fdt(self.blob,altered)

    def test_original_dtb_memory_inventory_tamper_rejected(self):
        altered=copy.deepcopy(self.dtb)
        altered["memoryRanges"]=[]
        with self.assertRaisesRegex(m.AuditError,"disagrees"):
            m.validate_fdt(self.blob,altered)

    def test_source_hypothesis_image_span_never_claims_allocation(self):
        report=m.audit(metadata(),self.dtb)
        span=report["candidateOriginalImageSpan"]
        self.assertEqual(span["start"],"0x40080000")
        self.assertEqual(span["endExclusive"],hex(0x40080000+0x180000))
        self.assertEqual(span["maxOfFileAndHeaderImageSize"],0x180000)
        self.assertEqual(report["ramBytesAdvertised"],0x80000000)
        self.assertFalse(report["hxl1ProtectedPoolAlreadyReserved"])
        self.assertFalse(report["canChooseCarveoutFromFdtAlone"])

    def test_missing_ram_rejected(self):
        f=copy.deepcopy(self.dtb)
        f["memoryRanges"]=[]
        with self.assertRaisesRegex(m.AuditError,"No FDT RAM"):
            m.audit(metadata(),f)

    def test_missing_source_reservation_is_not_memory_permission(self):
        f=d.parse_fdt(make_dtb(reserved=False,reserve=()))
        report=m.audit(metadata(),f)
        self.assertEqual(report["fdtReservationCount"],0)
        self.assertFalse(report["sourceFaithfulGuestMemoryAdapterReady"])
        self.assertIn("memblock", " ".join(report["unknownGuestPhysicalPlacements"]))

    def test_actual_dt_reservation_does_not_claim_protected_pool(self):
        report=m.audit(metadata(),self.dtb)
        self.assertEqual(report["fdtReservationCount"],2)
        self.assertEqual(report["fdtMemreserveAndReservedMemory"][0]["start"],
                         "0x60000000")
        self.assertFalse(report["hxl1ProtectedPoolAlreadyReserved"])

    def test_image_outside_guest_ram_rejected(self):
        f=d.parse_fdt(make_dtb(memory=(0x80000000,0x40000000)))
        with self.assertRaisesRegex(m.AuditError,"not fully within RAM"):
            m.audit(metadata(),f)

    def test_header_footprint_can_be_smaller_than_file_extent(self):
        report=m.audit(metadata(0x210000,0x180000),self.dtb)
        self.assertEqual(report["candidateOriginalImageSpan"]["maxOfFileAndHeaderImageSize"],
                         0x210000)

    def test_overlapping_memory_entries_rejected(self):
        f=copy.deepcopy(self.dtb)
        f["memoryRanges"].append(copy.deepcopy(f["memoryRanges"][0]))
        with self.assertRaisesRegex(m.AuditError,"Overlapping"):
            m.audit(metadata(),f)

    def test_unrelated_or_modified_kernel_hash_rejected(self):
        wrong=metadata()
        wrong["sha256"]="ff"*32
        with self.assertRaisesRegex(m.AuditError,"SHA-pinned"):
            m.audit(wrong,self.dtb)

    def test_half_initrd_bounds_rejected(self):
        f=copy.deepcopy(self.dtb)
        del f["chosenInitrd"]["linux,initrd-end"]
        with self.assertRaisesRegex(m.AuditError,"Only one"):
            m.audit(metadata(),f)

    def test_overflow_region_rejected(self):
        with self.assertRaises(m.AuditError):
            m.parse_interval({"start":"0xffffffffffffffff",
                              "endExclusive":"0x10000000000000001"},"test","fixture")

    def test_direct_script_help_with_python_isolation(self):
        script=Path(m.__file__).resolve()
        with tempfile.TemporaryDirectory() as dtemp:
            r=subprocess.run([sys.executable,"-I",str(script),"--help"],
                             cwd=dtemp,capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("--inventory",r.stdout)

    def test_no_fake_pool_or_execution(self):
        self.assertIn("never guesses",m.__doc__)
        self.assertNotIn("cpu_physical_memory_write",Path(m.__file__).read_text())
        self.assertFalse(hasattr(m,"run_qemu"))
        self.assertFalse(hasattr(m,"reserve_guest_ram"))

if __name__=="__main__":
    unittest.main()
