"""Synthetic full-runtime-FDT compare tests; no QEMU guest is executed."""
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
from unittest.mock import patch

from tools import y2q_hxl1_qemu_runtime_fdt_compare as c
from tools.test_y2q_hxl1_qemu_virt_dtb_inventory import make_dtb

CAPTURE=Path(c.__file__).with_name("run_y2q_hxl1_qemu_runtime_fdt_capture.sh")


def padded_guest_dtb(reserved:bool=False)->bytes:
    raw=bytearray(make_dtb(reserved=reserved,reserve=()))
    struct.pack_into(">I",raw,4,c.EXPECTED_BYTES)
    raw.extend(b"\0"*(c.EXPECTED_BYTES-len(raw)))
    return bytes(raw)


def fake_log(guest:bytes, x0=c.EXPECTED_GUEST_PA, complete:bool=True,
             wrong_header:bool=False)->str:
    hdr=bytearray(guest[:16])
    if wrong_header:hdr[0]^=0xff
    lines=[
       "The target architecture is set to \"aarch64\".",
       "Hardware assisted breakpoint 1 at 0x40080000",
       "Breakpoint 1, 0x40080000 in ?? ()",
       "HXL1_ENTRY_BREAKPOINT_HIT PC=0x40080000",
       f"X0=0x{x0:x} X1=0x0 X2=0x0 X3=0x0",
       "FDT_HEADER_AT_X0_START",
    ]
    for offset in (0,8):
        vals="  ".join(f"0x{b:02x}" for b in hdr[offset:offset+8])
        lines.append(f"0x{x0+offset:x}:  {vals}")
    lines.append("FDT_HEADER_AT_X0_END")
    if complete:lines.append(c.COMPLETE_MARKER)
    return "\n".join(lines)+"\n"


def prior_report(gen:bytes, guest:bytes)->dict:
    return {
        "target":c.TARGET,
        "sourceFactoryImageSha256":c.entry.PINNED_IMAGE_SHA,
        "sourceGeneratedQemuDtbSha256":hashlib.sha256(gen).hexdigest(),
        "entry":{
            "status":"GUEST_ENTRY_FDT_HEADER_CORRELATED",
            "guestFdtPointerValidated":True,
            "first16BytesHex":guest[:16].hex(),
            "fdtHeader":{"totalSizeBytes":c.EXPECTED_BYTES},
            "registers":{"X0":hex(c.EXPECTED_GUEST_PA),
                         "X1":"0x0","X2":"0x0","X3":"0x0"},
        },
        "runtimeFdtPhysicalInterval":{
            "start":hex(c.EXPECTED_GUEST_PA),
            "endExclusive":hex(c.EXPECTED_GUEST_PA+c.EXPECTED_BYTES),
            "sizeBytes":c.EXPECTED_BYTES,
        },
        "candidateImageSpan":{
            "start":"0x40080000","endExclusive":"0x443bb000",
            "status":"POSSIBLE_QEMU_IMAGE_PLACEMENT_NOT_PHYSICALLY_ATTESTED",
        }
    }


class RuntimeFdtCompareTests(unittest.TestCase):
    def setUp(self):
        self.generated=make_dtb(reserved=False,reserve=())
        self.runtime=padded_guest_dtb()
        self.prior=prior_report(self.generated,self.runtime)
        self.pin=patch.object(c.entry,"PINNED_DTB_SHA",
                              hashlib.sha256(self.generated).hexdigest())
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def test_full_runtime_dtb_and_previous_entry_correlated(self):
        report=c.compare_runtime(self.prior,self.generated,self.runtime,
                                 fake_log(self.runtime))
        self.assertTrue(report["fullRuntimeFdtCapturedAndParsed"])
        self.assertTrue(report["runtimeHeaderMatchesBothEntryGdbRuns"])
        self.assertTrue(report["guestRamProfileMatches"])
        self.assertEqual(report["runtimeFdtPhysicalSpan"]["start"],"0x48000000")
        self.assertEqual(report["runtimeFdtPhysicalSpan"]["sizeBytes"],1048576)
        self.assertEqual(report["runtimeFdtSha256"],hashlib.sha256(self.runtime).hexdigest())
        self.assertFalse(report["actualReservedProtectedPoolConfirmed"])
        self.assertFalse(report["actualKernelMemblockStateCaptured"])

    def test_runtime_generated_byte_difference_not_fake_error(self):
        report=c.compare_runtime(self.prior,self.generated,self.runtime,
                                 fake_log(self.runtime))
        self.assertFalse(report["runtimeFdtByteIdenticalToGenerated"])
        self.assertEqual(report["semanticInventoryDifferences"],{})

    def test_real_runtime_reserved_node_change_is_reported(self):
        guest=padded_guest_dtb(reserved=True)
        prior=prior_report(self.generated,guest)
        report=c.compare_runtime(prior,self.generated,guest,fake_log(guest))
        self.assertIn("reservedMemoryRanges",report["semanticInventoryDifferences"])
        self.assertEqual(report["runtimeReservedMemoryNodes"][0]["start"],"0x60000000")
        self.assertFalse(report["actualReservedProtectedPoolConfirmed"])

    def test_missing_complete_gdb_marker_is_not_a_dump(self):
        with self.assertRaisesRegex(c.RuntimeFdtError,"completion"):
            c.compare_runtime(self.prior,self.generated,self.runtime,
                              fake_log(self.runtime,complete=False))

    def test_wrong_kernel_pc_or_x0_is_rejected(self):
        with self.assertRaisesRegex(c.RuntimeFdtError,"GDB guest PC/X0"):
            c.compare_runtime(self.prior,self.generated,self.runtime,
                              fake_log(self.runtime,x0=0x48001000))

    def test_printed_first16_must_match_dump_file(self):
        with self.assertRaisesRegex(c.RuntimeFdtError,"GDB guest PC/X0"):
            c.compare_runtime(self.prior,self.generated,self.runtime,
                              fake_log(self.runtime,wrong_header=True))

    def test_tampered_prior_gdb_header_fails(self):
        prior=copy.deepcopy(self.prior)
        prior["entry"]["first16BytesHex"]="00"*16
        with self.assertRaisesRegex(c.RuntimeFdtError,"previously observed"):
            c.compare_runtime(prior,self.generated,self.runtime,
                              fake_log(self.runtime))

    def test_wrong_exact_capture_length_fails(self):
        with self.assertRaisesRegex(c.RuntimeFdtError,"exact 1MiB"):
            c.compare_runtime(self.prior,self.generated,self.runtime[:-1],
                              fake_log(self.runtime))

    def test_stale_generated_machine_profile_rejected(self):
        with patch.object(c.entry,"PINNED_DTB_SHA","f"*64):
            with self.assertRaisesRegex(c.RuntimeFdtError,"original QEMU"):
                c.compare_runtime(self.prior,self.generated,self.runtime,
                                  fake_log(self.runtime))

    def test_unexpected_guest_ram_rejected(self):
        other=padded_guest_dtb()
        bad=bytearray(other)
        # Change source device-tree memory node by making fixture from a
        # different memory start; this changes the generated RAM layout.
        modified=bytearray(make_dtb(reserve=(),reserved=False,
                                    memory=(0x80000000,0x40000000)))
        struct.pack_into(">I",modified,4,c.EXPECTED_BYTES)
        modified.extend(b"\0"*(c.EXPECTED_BYTES-len(modified)))
        prior=prior_report(self.generated,bytes(modified))
        with self.assertRaisesRegex(c.RuntimeFdtError,"RAM layout differs"):
            c.compare_runtime(prior,self.generated,bytes(modified),
                              fake_log(bytes(modified)))

    def test_guest_runtime_fdt_overlap_is_reported_not_reserved(self):
        prior=prior_report(self.generated,self.runtime)
        prior["candidateImageSpan"]={"start":"0x47f80000",
                                      "endExclusive":"0x48080000"}
        report=c.compare_runtime(prior,self.generated,self.runtime,
                                 fake_log(self.runtime))
        self.assertIsNotNone(report["candidateImageOverlapWithRuntimeFdt"])
        self.assertFalse(report["qemuRkpMemoryAdapterReady"])

    def test_shell_source_syntax(self):
        r=subprocess.run(["bash","-n",str(CAPTURE)],
                         capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr)

    def test_shell_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/"existing"
            out.mkdir()
            (out/"old.log").write_text("preserved")
            result=subprocess.run(["bash",str(CAPTURE),str(out)],
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn("already exists",result.stderr)
            self.assertEqual((out/"old.log").read_text(),"preserved")

    def test_invalid_kernel_hash_refused_before_qemu(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"s20-artifacts").mkdir()
            (root/"s20-artifacts/kernel.bin").write_bytes(b"not factory")
            env=os.environ.copy()
            env["HOME"]=str(root)
            out=root/"new"
            r=subprocess.run(["bash",str(CAPTURE),str(out)],
                             capture_output=True,text=True,env=env,timeout=10)
            self.assertEqual(r.returncode,2)
            self.assertIn("SHA mismatch",r.stderr)
            self.assertFalse(out.exists())

    def test_capture_is_read_only_and_bounded(self):
        content=CAPTURE.read_text()
        self.assertIn("dump binary memory",content)
        self.assertIn("hbreak *$ENTRY_PC",content)
        self.assertIn("GUEST_X0=0x48000000",content)
        self.assertIn("FDT_BYTES=1048576",content)
        self.assertIn("TIME_LIMIT=60",content)
        self.assertIn("trap cleanup EXIT",content)
        self.assertNotIn("set {",content)
        self.assertNotIn("restore ",content)
        self.assertNotIn("fastboot ",content)
        self.assertNotIn("adb ",content)

    def test_direct_script_help_in_isolated_python(self):
        script=Path(c.__file__).resolve()
        with tempfile.TemporaryDirectory() as d:
            r=subprocess.run([sys.executable,"-I",str(script),"--help"],
                             cwd=d,capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn("--runtime-dtb",r.stdout)

if __name__=="__main__":
    unittest.main()
