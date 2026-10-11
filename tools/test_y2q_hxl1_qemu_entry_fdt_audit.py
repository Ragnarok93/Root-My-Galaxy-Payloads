"""Synthetic guest ARM64 X0/FDT header parsing and no-device launch guards."""
from pathlib import Path
import hashlib
import os
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_qemu_entry_fdt_audit as a
from tools.test_y2q_hxl1_qemu_virt_dtb_inventory import make_dtb

CAPTURE=Path(__file__).with_name("run_y2q_hxl1_qemu_entry_fdt_capture.sh")
GUEST_FDT_PA=0x47f00000

def gdb_log(fdt=make_dtb(),pc=a.ENTRY_PC,x0=GUEST_FDT_PA,
            include_header=True,missing_line=False)->str:
    header=fdt[:16]
    s=("The target architecture is set to aarch64\n"
       "Hardware assisted breakpoint 1 at 0x40080000\n"
       f"Breakpoint 1, 0x{pc:x}\n"
       f"HXL1_ENTRY_BREAKPOINT_HIT PC=0x{pc:x}\n"
       f"X0=0x{x0:x} X1=0x0 X2=0x0 X3=0x0\n"
       "FDT_HEADER_AT_X0_START\n")
    if include_header:
        row1="\t".join("0x%02x"%b for b in header[:8])
        row2="\t".join("0x%02x"%b for b in header[8:])
        s+=f"0x{x0:x}:\t{row1}\n0x{x0+8:x}:\t{row2}\n"
    elif missing_line:
        s+=f"Cannot access memory at address 0x{x0:x}\n"
    s+="FDT_HEADER_AT_X0_END\n"
    return s


def boot_report():
    return {
        "inputKernelSha256":a.PINNED_IMAGE_SHA,
        "inputFdtSha256":hashlib.sha256(make_dtb()).hexdigest(),
        "ramBytesAdvertised":2147483648,
        "ram":[{"start":"0x40000000","endExclusive":"0xc0000000"}],
        "candidateOriginalImageSpan":{"start":"0x40080000",
                                     "endExclusive":"0x443bb000"}
    }


class EntryFdtTests(unittest.TestCase):
    def test_original_entry_x0_header_and_image_overlap(self):
        g=a.parse_gdb(gdb_log())
        self.assertEqual(g["status"],"GUEST_ENTRY_FDT_HEADER_CORRELATED")
        self.assertTrue(g["guestFdtPointerValidated"])
        self.assertTrue(g["bootProtocolRegistersZero"])
        self.assertEqual(g["registers"]["X0"],hex(GUEST_FDT_PA))
        self.assertEqual(g["fdtHeader"]["magic"],"0xd00dfeed")
        self.assertEqual(g["runtimeFdtPhysicalInterval"]["start"],hex(GUEST_FDT_PA))
        with patch.object(a,"PINNED_DTB_SHA",hashlib.sha256(make_dtb()).hexdigest()):
            report=a.correlate(g,boot_report(),make_dtb())
        self.assertIsNone(report["candidateImageOverlapWithRuntimeFdt"])
        self.assertTrue(report["protectedRkpPoolReservationNotProven"])
        self.assertFalse(report["qemuRkpGuestMemoryAdapterReady"])
    def test_entry_missing_breakpoint_is_inconclusive(self):
        r=a.parse_gdb("No breakpoint fired\n")
        self.assertEqual(r["status"],"BREAKPOINT_NOT_UNIQUELY_OBSERVED")
        self.assertFalse(r["bootEntryObserved"])
    def test_entry_duplicate_marker_is_not_pass(self):
        g=gdb_log()
        self.assertEqual(a.parse_gdb(g+g)["status"],"BREAKPOINT_NOT_UNIQUELY_OBSERVED")
    def test_entry_wrong_pc_cannot_claim_kernel(self):
        self.assertEqual(a.parse_gdb(gdb_log(pc=0x40090000))["status"],
                         "BREAKPOINT_NOT_AT_PINNED_IMAGE_ENTRY")
    def test_x0_memory_unreadable_is_inconclusive(self):
        r=a.parse_gdb(gdb_log(include_header=False,missing_line=True))
        self.assertEqual(r["status"],"FDT_GUEST_MEMORY_UNREADABLE")
    def test_partial_header_must_not_pass(self):
        s=gdb_log()
        s=s.replace(f"0x{GUEST_FDT_PA+8:x}:",f"0x{GUEST_FDT_PA+16:x}:")
        self.assertEqual(a.parse_gdb(s)["status"],"FDT_READ_NOT_CONTIGUOUS_FROM_X0")
    def test_non_fdt_magic_is_refused(self):
        blob=bytearray(make_dtb())
        blob[0]=0x77
        self.assertEqual(a.parse_gdb(gdb_log(blob))["status"],"GUEST_X0_NOT_AN_FDT_MAGIC")
    def test_unaligned_x0_is_refused(self):
        self.assertEqual(a.parse_gdb(gdb_log(x0=GUEST_FDT_PA+1))["status"],
                         "FDT_HEADER_INVALID_OR_UNALIGNED")
    def test_fdt_outside_ram_refused(self):
        r=a.parse_gdb(gdb_log(x0=0xbfffffe0))
        self.assertEqual(r["status"],"FDT_NOT_FULLY_CONTAINED_IN_PROFILE_RAM")
    def test_fdt_in_candidate_image_span_detects_overlap(self):
        loc=0x44000000
        g=a.parse_gdb(gdb_log(x0=loc))
        with patch.object(a,"PINNED_DTB_SHA",hashlib.sha256(make_dtb()).hexdigest()):
            report=a.correlate(g,boot_report(),make_dtb())
        self.assertIsNotNone(report["candidateImageOverlapWithRuntimeFdt"])
        self.assertFalse(report["qemuRkpGuestMemoryAdapterReady"])
    def test_pinned_dtb_mismatch_refused(self):
        with self.assertRaisesRegex(a.EntryEvidenceError,"generated DTB"):
            a.correlate(a.parse_gdb(gdb_log()),boot_report(),make_dtb())
    def test_image_evidence_mismatch_refused(self):
        report=boot_report()
        report["inputKernelSha256"]="0"*64
        with self.assertRaisesRegex(a.EntryEvidenceError,"factory Image"):
            a.correlate(a.parse_gdb(gdb_log()),report,make_dtb())
    def test_shell_syntax(self):
        r=subprocess.run(["bash","-n",str(CAPTURE)],
                         capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
    def test_shell_preserves_existing_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/"existing"
            dest.mkdir()
            (dest/"evidence").write_text("keep")
            r=subprocess.run(["bash",str(CAPTURE),str(dest)],
                             capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,2)
            self.assertIn("Output exists",r.stderr)
            self.assertEqual((dest/"evidence").read_text(),"keep")
    def test_shell_bad_stock_image_refused_before_qemu(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"s20-artifacts").mkdir()
            (root/"s20-artifacts/kernel.bin").write_bytes(b"not original")
            env=os.environ.copy()
            env["HOME"]=str(root)
            dest=root/"capture"
            r=subprocess.run(["bash",str(CAPTURE),str(dest)],env=env,
                             capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,2)
            self.assertIn("Image SHA mismatch",r.stderr)
            self.assertFalse(dest.exists())
    def test_launcher_never_writes_guest_ram(self):
        data=CAPTURE.read_text()
        self.assertIn("-S -gdb",data)
        self.assertIn("x/16bx",data)
        self.assertIn("hbreak *$ENTRY_PC",data)
        self.assertNotIn("set {",data)
        self.assertNotIn("restore ",data)
        self.assertNotIn("fastboot ",data)
        self.assertNotIn("adb ",data)
        self.assertIn("trap cleanup EXIT",data)
    def test_direct_python_cli_isolated(self):
        script=Path(a.__file__).resolve()
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run(["python3","-I",str(script),"--help"],
                             cwd=d,capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("--gdb",r.stdout)


if __name__=="__main__":
    unittest.main()
