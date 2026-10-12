"""Synthetic QEMU device-tree self-reservation canary tests (NO kernel execution)."""
from __future__ import annotations
import copy
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from tools import y2q_hxl1_qemu_fdt_canary as canary
from tools import y2q_hxl1_qemu_fdt_canary_verify as verify
from tools import y2q_hxl1_qemu_virt_dtb_inventory as fdt
from tools.test_y2q_hxl1_qemu_virt_dtb_inventory import make_dtb

ROOT=Path(__file__).resolve().parent
CAPTURE=ROOT/"run_y2q_hxl1_qemu_fdt_canary_capture.sh"

def padded(blob:bytes)->bytes:
    b=bytearray(blob)
    struct.pack_into(">I",b,4,canary.FDT_SIZE)
    if len(b)>canary.FDT_SIZE:
        raise ValueError("fixture too long")
    b.extend(bytes(canary.FDT_SIZE-len(b)))
    return bytes(b)

def gdblog(delivered:bytes)->str:
    x0=canary.FDT_PA
    parts=[
        'The target architecture is set to "aarch64".',
        'Breakpoint 1, 0x40080000 in ?? ()',
        'HXL1_ENTRY_BREAKPOINT_HIT PC=0x40080000',
        f'X0=0x{x0:x} X1=0x0 X2=0x0 X3=0x0',
        'FDT_HEADER_AT_X0_START',
    ]
    for offset in (0,8):
        cells="  ".join(f"0x{b:02x}" for b in delivered[offset:offset+8])
        parts.append(f"0x{x0+offset:x}:  {cells}")
    parts.extend(['FDT_HEADER_AT_X0_END',
                  verify.DECLARED_MARKER+str(len(delivered)),
                  verify.MARKER+str(len(delivered))])
    return "\n".join(parts)+"\n"

class FdtCanaryTests(unittest.TestCase):
    def setUp(self):
        self.orig=padded(make_dtb(reserve=(),reserved=False))
        self.override,self.manifest=canary.make_canary(self.orig,check_pinned=False)
        self.baseline=self.orig
        self.guest=self.override

    def probe(self,guest=None,log=None,manifest=None,override=None,
              require_self_coverage=True):
        return verify.report_delivery(
            self.orig,override if override is not None else self.override,
            self.baseline,
            guest if guest is not None else self.guest,
            log if log is not None else gdblog(self.guest),
            manifest if manifest is not None else self.manifest,
            strict_sha=False,require_self_coverage=require_self_coverage)

    def test_add_only_one_memreserve_and_preserve_all_device_nodes(self):
        prior=fdt.parse_fdt(self.orig)
        new=fdt.parse_fdt(self.override)
        self.assertEqual(new["memoryReservationEntries"],[
            {"start":"0x48000000","endExclusive":"0x48101000","sizeBytes":1052672}])
        self.assertEqual(prior["memoryRanges"],new["memoryRanges"])
        self.assertEqual(prior["nodeCount"],new["nodeCount"])
        self.assertEqual(prior["chosenInitrd"],new["chosenInitrd"])
        self.assertTrue(self.manifest["originalStructureAndStringsByteIdentical"])
        self.assertFalse(self.manifest["rkpProtectedPoolReserved"])

    def test_builder_refuses_preexisting_reservation(self):
        with self.assertRaisesRegex(canary.CanaryError,"already reserves"):
            canary.make_canary(make_dtb(reserved=False),check_pinned=False)

    def test_builder_refuses_nonmatching_memory_profile(self):
        with self.assertRaisesRegex(canary.CanaryError,"RAM"):
            canary.make_canary(make_dtb(reserve=(),reserved=False,
                                       memory=(0x80000000,0x40000000)),
                               check_pinned=False)

    def test_builder_refuses_extra_untracked_source_padding(self):
        with self.assertRaisesRegex(canary.CanaryError,"trailing"):
            canary.make_canary(self.orig+bytes(4),check_pinned=False)

    def test_builder_pins_owner_generated_dtb_sha(self):
        with self.assertRaisesRegex(canary.CanaryError,"SHA mismatch"):
            canary.make_canary(self.orig,check_pinned=True)

    def test_canary_reaches_synthetic_guest_entry(self):
        report=self.probe()
        self.assertTrue(report["diagnosticCanaryDelivered"])
        self.assertEqual(report["deliveredGuestFdtPhysicalAddress"],"0x48000000")
        self.assertEqual(report["deliveredSelfReservation"]["sizeBytes"],1052672)
        self.assertEqual(report["deliveredGuestFdtTotalSize"],1048592)
        self.assertTrue(report["captureLengthMatchesDeclaredFdtBytes"])
        self.assertFalse(report["hxl1RkpProtectedPoolReserved"])
        self.assertFalse(report["linuxMemblockReservationObserved"])

    def test_mib_boundary_canary_addition_requires_more_than_one_mib(self):
        self.assertEqual(len(self.orig),1048576)
        self.assertEqual(len(self.override),1048592)
        self.assertEqual(self.manifest["overrideFdtTotalSizeBytes"],1048592)
        self.assertEqual(self.manifest["addedMemreserve"]["sizeBytes"],1052672)
        self.assertEqual(self.manifest["fdtReservationPageAlignment"],4096)

    def test_old_fixed_one_mib_dump_is_rejected_with_exact_size_diagnostic(self):
        bad=self.guest[:1048576]
        with self.assertRaisesRegex(verify.DeliveryError,
                                    "header totalsize=1048592 bytes, captured=1048576"):
            self.probe(guest=bad,log=gdblog(self.guest))

    def test_mismatched_gdb_declared_size_is_rejected(self):
        log=gdblog(self.guest).replace(
            verify.DECLARED_MARKER+str(len(self.guest)),
            verify.DECLARED_MARKER+"1048576")
        with self.assertRaisesRegex(verify.DeliveryError,"complete header-sized"):
            self.probe(log=log)

    def test_missing_guest_header_length_marker_is_rejected(self):
        log=gdblog(self.guest).replace(
            verify.DECLARED_MARKER+str(len(self.guest)),"")
        with self.assertRaisesRegex(verify.DeliveryError,"complete header-sized"):
            self.probe(log=log)

    def test_guest_fdt_larger_than_page_rounded_reservation_refused(self):
        size=1052673
        guest=bytearray(self.guest)
        struct.pack_into(">I",guest,4,size)
        guest.extend(bytes(size-len(guest)))
        with self.assertRaisesRegex(verify.DeliveryError,"complete runtime FDT"):
            self.probe(guest=bytes(guest),log=gdblog(bytes(guest)))

    def test_launcher_does_not_assume_one_mib_after_memreserve_insertion(self):
        sh=CAPTURE.read_text()
        self.assertIn("HXL1_CANARY_GUEST_FDT_DECLARED_BYTES",sh)
        self.assertIn("fdt_declared",sh)
        self.assertIn("len(raw)==total",sh)
        self.assertNotIn("FDT_LENGTH=1048576",sh)
        self.assertIn("MAX_FDT_LENGTH=8388608",sh)

    def test_observed_2117184_byte_runtime_fdt_delivers_canary_but_undersized(self):
        # Exactly the user's v2 reported guest header. The original source
        # 1MiB DTB grew by 16B and QEMU later expanded it to 2,117,184B.
        n=2117184
        guest=bytearray(self.guest)
        struct.pack_into(">I",guest,4,n)
        guest.extend(bytes(n-len(guest)))
        log=gdblog(bytes(guest))
        result=self.probe(guest=bytes(guest),log=log,
                          require_self_coverage=False)
        self.assertEqual(result["classification"],
                         "DELIVERED_BUT_SELF_RESERVATION_UNDERSIZED")
        self.assertTrue(result["diagnosticCanaryDelivered"])
        self.assertFalse(result["selfReservationCoversCompleteGuestFdt"])
        self.assertEqual(result["deliveredGuestFdtTotalSize"],n)
        self.assertEqual(result["deliveredSelfReservation"]["sizeBytes"],1052672)
        self.assertEqual(result["observedFdtMinimumPageRoundedReserveBytes"],2117632)
        self.assertEqual(result["observedFdtMinimumPageRoundedReserveEndExclusive"],
                         "0x48205000")
        self.assertFalse(result["linuxMemblockReservationObserved"])
        self.assertFalse(result["hxl1RkpProtectedPoolReserved"])
        with self.assertRaisesRegex(verify.DeliveryError,
                                    "Canary reached guest entry but does not cover"):
            self.probe(guest=bytes(guest),log=log)

    def test_explicit_measured_reservation_covers_observed_guest_growth(self):
        measured=2117632
        override,manifest=canary.make_canary(
            self.orig,check_pinned=False,self_reserve_bytes=measured)
        self.assertEqual(manifest["selfReservationExplicitGuestMeasuredBytes"],measured)
        guest=bytearray(override)
        struct.pack_into(">I",guest,4,2117184)
        guest.extend(bytes(2117184-len(guest)))
        report=self.probe(guest=bytes(guest),log=gdblog(bytes(guest)),
                          manifest=manifest,override=override)
        self.assertEqual(report["classification"],"DELIVERED_AND_FULLY_COVERED")
        self.assertTrue(report["selfReservationCoversCompleteGuestFdt"])
        self.assertEqual(report["deliveredSelfReservation"]["endExclusive"],
                         "0x48205000")
        self.assertFalse(report["hxl1RkpProtectedPoolReserved"])

    def test_measured_self_reserve_refuses_unaligned_and_insufficient_size(self):
        for bad in (2117184,1052671,0,8388609):
            with self.subTest(reserve_bytes=bad),self.assertRaises(canary.CanaryError):
                canary.make_canary(self.orig,False,self_reserve_bytes=bad)
        with self.assertRaisesRegex(canary.CanaryError,"cannot truncate"):
            canary.make_canary(self.orig,False,self_reserve_bytes=1048576)

    def test_mismatched_measured_canary_manifest_refused(self):
        override,manifest=canary.make_canary(self.orig,False,2117632)
        altered=copy.deepcopy(manifest)
        altered["selfReservationExplicitGuestMeasuredBytes"]=2113536
        with self.assertRaises(verify.DeliveryError):
            self.probe(override=override,manifest=altered,
                       guest=override,log=gdblog(override))


    def test_prelaunch_v3_measured_canary_validates_exactly(self):
        # Regression for owner's actual v3 prelaunch rejection: the reserve
        # can exceed the *override* DTB size when QEMU expands guest FDT.
        override,manifest=canary.make_canary(self.orig,False,2117632)
        from unittest.mock import patch
        with patch.object(canary,"SOURCE_SHA",hashlib.sha256(self.orig).hexdigest()):
            verified=canary.verify_existing_canary(self.orig,override,manifest)
        self.assertEqual(verified["addedMemreserve"]["sizeBytes"],2117632)
        self.assertEqual(verified["selfReservationExplicitGuestMeasuredBytes"],2117632)
        self.assertEqual(verified["overrideFdtSha256"],
                         hashlib.sha256(override).hexdigest())
        self.assertFalse(verified["rkpProtectedPoolReserved"])

    def test_prelaunch_v3_manifest_and_fdt_tamper_refused(self):
        override,manifest=canary.make_canary(self.orig,False,2117632)
        modified=copy.deepcopy(manifest)
        modified["addedMemreserve"]["sizeBytes"]=1052672
        with self.assertRaisesRegex(canary.CanaryError,"manifest"):
            canary.verify_existing_canary(self.orig,override,modified,False)
        modified=copy.deepcopy(manifest)
        modified["selfReservationExplicitGuestMeasuredBytes"]=None
        with self.assertRaises(canary.CanaryError):
            canary.verify_existing_canary(self.orig,override,modified,False)
        tampered=bytearray(override)
        struct.pack_into(">I",tampered,28,2)
        with self.assertRaisesRegex(canary.CanaryError,"bytes"):
            canary.verify_existing_canary(self.orig,bytes(tampered),manifest,False)
        with self.assertRaisesRegex(canary.CanaryError,"integer"):
            canary.verify_existing_canary(
                self.orig,override,
                {**manifest,"selfReservationExplicitGuestMeasuredBytes":True},False)

    def test_prelaunch_script_uses_exact_reconstruction_not_minimum_reserve(self):
        sh=CAPTURE.read_text()
        self.assertIn('--verify-dir "$CANARY_DIR"',sh)
        self.assertIn('y2q_hxl1_qemu_fdt_canary.py',sh)
        self.assertNotIn('struct.unpack_from(">QQ",blob,off_rsv)!=(0x48000000,',sh)
        self.assertLess(sh.index("--verify-dir"),sh.index('mkdir -p -- "$OUT"'))

    def test_prelaunch_cli_refuses_unpinned_source_before_qemu(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            d=root/"canary"
            d.mkdir()
            (root/"source.dtb").write_bytes(self.orig)
            (d/"canary-override.dtb").write_bytes(self.override)
            (d/"canary-construction.json").write_text(
                __import__("json").dumps(self.manifest))
            res=subprocess.run([
                sys.executable,str(Path(canary.__file__).resolve()),
                "--source",str(root/"source.dtb"),
                "--verify-dir",str(d)],
                capture_output=True,text=True,timeout=10)
            self.assertEqual(res.returncode,2)
            self.assertIn("SHA mismatch",res.stderr)
            self.assertEqual(sorted(p.name for p in d.iterdir()),
                             ["canary-construction.json","canary-override.dtb"])

    def test_guest_without_canary_fails_closed(self):
        with self.assertRaisesRegex(verify.DeliveryError,"not present exactly"):
            self.probe(guest=self.baseline,log=gdblog(self.baseline))

    def test_extra_unexpected_reservation_is_not_accepted(self):
        other=fdt.parse_fdt(self.guest)
        self.assertEqual(len(other["memoryReservationEntries"]),1)
        altered=bytearray(self.guest)
        off=struct.unpack_from(">I",altered,16)[0]
        struct.pack_into(">QQ",altered,off,0x60000000,4096)
        with self.assertRaises(verify.DeliveryError):
            self.probe(guest=bytes(altered),log=gdblog(bytes(altered)))

    def test_modified_override_fdt_is_refused(self):
        changed=bytearray(self.override)
        struct.pack_into(">I",changed,28,1)  # change boot CPU ID, preserve parseable FDT
        with self.assertRaisesRegex(verify.DeliveryError,"beyond the one canary"):
            self.probe(override=bytes(changed))

    def test_mismatched_constructor_manifest_refused(self):
        m=copy.deepcopy(self.manifest)
        m["overrideFdtSha256"]="11"*32
        with self.assertRaisesRegex(verify.DeliveryError,"manifest"):
            self.probe(manifest=m)

    def test_missing_gdb_complete_marker_fails(self):
        with self.assertRaisesRegex(verify.DeliveryError,"one complete"):
            self.probe(log=gdblog(self.guest).replace(verify.MARKER,""))

    def test_bad_entry_x0_is_not_accepted(self):
        with self.assertRaisesRegex(verify.DeliveryError,"entry or X0"):
            self.probe(log=gdblog(self.guest).replace(
                "X0=0x48000000","X0=0x48001000"))

    def test_fdt_header_mismatch_refused(self):
        changed=bytearray(self.guest)
        changed[0]^=0xff
        with self.assertRaisesRegex(verify.DeliveryError,"Invalid delivered guest FDT header"):
            self.probe(guest=bytes(changed),log=gdblog(self.guest))

    def test_shell_syntax_and_guard_on_existing_evidence(self):
        r=subprocess.run(["bash","-n",str(CAPTURE)],text=True,
                         capture_output=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp)
            out=d/"existing";out.mkdir()
            (out/"old.txt").write_text("original")
            process=subprocess.run(["bash",str(CAPTURE),str(d/"missing"),str(out)],
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(process.returncode,2)
            self.assertIn("Output exists",process.stderr)
            self.assertEqual((out/"old.txt").read_text(),"original")

    def test_capture_cannot_reach_qemu_with_wrong_kernel_sha(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"s20-artifacts").mkdir()
            (root/"s20-artifacts/kernel.bin").write_bytes(b"bad stock")
            can_dir=root/"can"
            can_dir.mkdir()
            (can_dir/"canary-override.dtb").write_bytes(self.override)
            (can_dir/"canary-construction.json").write_text("{}")
            env=os.environ.copy();env["HOME"]=str(root)
            out=root/"new"
            result=subprocess.run(["bash",str(CAPTURE),str(can_dir),str(out)],
                                  env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn("Stock kernel SHA256 mismatch",result.stderr)
            self.assertFalse(out.exists())

    def test_capture_is_local_readonly_and_bounded(self):
        sh=CAPTURE.read_text()
        self.assertIn('-dtb "$CANARY_DIR/canary-override.dtb"',sh)
        self.assertIn("dump binary memory",sh)
        self.assertIn("hbreak *$ENTRY_PC",sh)
        self.assertIn("trap cleanup EXIT",sh)
        self.assertIn("TIME_LIMIT=60",sh)
        self.assertNotIn("fastboot ",sh)
        self.assertNotIn("adb ",sh)
        self.assertNotIn("set {",sh)

    def test_cli_direct_invocation_isolated_from_checkout(self):
        for script in (canary.__file__,verify.__file__):
            with tempfile.TemporaryDirectory() as d:
                process=subprocess.run([sys.executable,"-I",str(script),"--help"],
                                       cwd=d,capture_output=True,text=True,timeout=10)
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertIn("--",process.stdout)

if __name__=="__main__":
    unittest.main()
