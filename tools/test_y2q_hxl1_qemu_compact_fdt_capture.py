"""Synthetic-only original-image QEMU compact runtime-FDT capture attestations."""
from __future__ import annotations
import hashlib
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import y2q_hxl1_qemu_compact_fdt_capture as a
from tools import y2q_hxl1_qemu_fdt_canary as canary
from tools.test_y2q_hxl1_qemu_virt_dtb_inventory import make_dtb


def compact():
    orig=make_dtb(reserve=(),reserved=False)
    return canary.make_canary(
        orig,check_pinned=False,self_reserve_bytes=a.LIMIT)[0]

def runtime(total:int=70000):
    b=bytearray(compact())
    if total<len(b):
        raise ValueError("negative synthetic padding")
    struct.pack_into(">I",b,4,total)
    b.extend(bytes(total-len(b)))
    return bytes(b)

def log_for(blob:bytes):
    addr=a.FDT_PA
    chunk=[]
    for off in (0,8):
        chunk.append(f"0x{addr+off:x}:\t"+
                     "\t".join(f"0x{v:02x}" for v in blob[off:off+8]))
    return (
        "Breakpoint 1, 0x40080000 in ?? ()\n"
        "HXL1_ENTRY_BREAKPOINT_HIT PC=0x40080000\n"
        f"X0=0x{addr:x} X1=0x0 X2=0x0 X3=0x0\n"
        "FDT_HEADER_AT_X0_START\n"+
        "\n".join(chunk)+"\n"
        "FDT_HEADER_AT_X0_END\n"+
        f"{a.GDB_DECLARED}{len(blob)}\n"
        f"{a.GDB_COMPLETE}{len(blob)}\n")

class CompactCaptureTests(unittest.TestCase):
    def test_attest_synthetic_runtime_guest_under_limit(self):
        raw=runtime()
        result=a.verify_capture(raw,log_for(raw))
        self.assertTrue(result["guestFdtWithin2MiB"])
        self.assertEqual(result["guestFdtTotalBytes"],len(raw))
        self.assertEqual(result["diagSelfReservation"]["sizeBytes"],a.LIMIT)
        self.assertTrue(result["selfReservationCoversGuestFdt"])
        self.assertFalse(result["guestLinuxMemblockExclusionVerified"])

    def test_reject_over_limit_runtime_even_with_source_canary(self):
        blob=runtime(a.LIMIT+0x1000)
        result=a.verify_capture(blob,log_for(blob))
        self.assertFalse(result["guestFdtWithin2MiB"])
        self.assertEqual(result["status"],"DELIVERED_COMPACT_OVERRIDE_BUT_RUNTIME_FDT_OVER_2M")
        self.assertFalse(result["selfReservationCoversGuestFdt"])

    def test_early_arm64_fdt_boundary_exactly_two_mebibytes(self):
        blob=runtime(a.LIMIT)
        result=a.verify_capture(blob,log_for(blob))
        self.assertTrue(result["guestFdtWithin2MiB"])
        self.assertEqual(result["guestFdtTotalBytes"],2097152)

    def test_original_v3_observed_2117184_bytes_exceeds_limit(self):
        blob=runtime(2117184)
        result=a.verify_capture(blob,log_for(blob))
        self.assertEqual(result["guestFdtTotalBytes"]-a.LIMIT,20032)
        self.assertFalse(result["guestFdtWithin2MiB"])

    def test_truncated_guest_read_cannot_pass(self):
        blob=runtime()
        with self.assertRaisesRegex(a.CompactError,"declared header"):
            a.verify_capture(blob[:-8],log_for(blob))

    def test_missing_marker_cannot_claim_full_runtime(self):
        blob=runtime()
        log=log_for(blob).replace(a.GDB_COMPLETE+str(len(blob)),"")
        with self.assertRaisesRegex(a.CompactError,"marker"):
            a.verify_capture(blob,log)

    def test_header_gdb_mismatch_cannot_claim_complete_capture(self):
        blob=runtime()
        badlog=log_for(blob).replace(
            a.GDB_DECLARED+str(len(blob)),
            a.GDB_DECLARED+str(len(blob)+16))
        with self.assertRaisesRegex(a.CompactError,"marker"):
            a.verify_capture(blob,badlog)

    def test_header_bytes_must_match_gdb(self):
        blob=runtime()
        altered=log_for(blob).replace("0xd0","0xd1",1)
        with self.assertRaises(a.CompactError):
            a.verify_capture(blob,altered)

    def test_wrong_guest_fdt_pointer_refused(self):
        blob=runtime()
        log=log_for(blob).replace("X0=0x48000000","X0=0x48001000")
        with self.assertRaises(a.CompactError):
            a.verify_capture(blob,log)

    def test_guest_reservation_must_not_be_deleted(self):
        buf=bytearray(runtime())
        map_off=struct.unpack_from(">I",buf,16)[0]
        struct.pack_into(">QQ",buf,map_off,0,0)
        with self.assertRaisesRegex(a.CompactError,"lost or changed"):
            a.verify_capture(bytes(buf),log_for(bytes(buf)))

    def test_unexpected_second_memreserve_rejected(self):
        buf=bytearray(runtime())
        map_off=struct.unpack_from(">I",buf,16)[0]
        struct.pack_into(">QQ",buf,map_off,0x48000000,0x4000)
        with self.assertRaisesRegex(a.CompactError,"lost or changed"):
            a.verify_capture(bytes(buf),log_for(bytes(buf)))

    def test_gdb_script_is_original_image_entry_and_readonly(self):
        with tempfile.TemporaryDirectory() as t:
            s=a.gdb_script(12349,Path(t))
        self.assertIn("hbreak *0x40080000",s)
        self.assertIn("dump binary memory",s)
        self.assertIn("HXL1_COMPACT_FDT_GUEST_DECLARED_BYTES",s)
        self.assertIn("HXL1_COMPACT_FDT_DUMP_COMPLETED",s)
        self.assertIn("0xc0000000",s)
        self.assertNotIn("set {",s)
        self.assertNotIn("restore ",s)

    def test_capture_requires_stock_sha_and_compact_manifest(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            image=root/"kernel.bin"
            image.write_bytes(b"not OEM stock")
            with self.assertRaisesRegex(a.gate.GateError,"SHA256 mismatch"):
                a.verify_input(root,image)

    def test_readonly_offline_cli_help_under_python_isolation(self):
        with tempfile.TemporaryDirectory() as t:
            run=subprocess.run(
                [sys.executable,"-I",str(Path(a.__file__)),"--help"],
                cwd=t,capture_output=True,text=True,timeout=10)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn("--audit-dir",run.stdout)

    def test_source_requires_fresh_output_and_no_phone_tools(self):
        source=Path(a.__file__).read_text()
        for bad in ("fastboot flash","adb shell","-nic user",
                    "cpu_physical_memory_write","memory_write("):
            self.assertNotIn(bad,source)
        self.assertIn("gate.safe_output(",source)
        self.assertIn("proc.terminate()",source)
        self.assertIn("proc.kill()",source)
        self.assertIn("status",source)

if __name__=="__main__":
    unittest.main()
