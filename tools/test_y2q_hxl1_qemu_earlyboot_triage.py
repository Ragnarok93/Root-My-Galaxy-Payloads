"""No-device tests for SHA-pinned factory HXL1 QEMU first-failure triage."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_qemu_earlyboot_triage as t

class QemuFirstFailureTests(unittest.TestCase):
    def make_image(self, directory):
        raw=bytearray(128)
        struct.pack_into("<Q",raw,8,0x80000)
        struct.pack_into("<Q",raw,16,0x100000)
        raw[0x38:0x3c]=t.MAGIC
        p=Path(directory)/"kernel.bin"
        p.write_bytes(raw)
        return p,hashlib.sha256(raw).hexdigest()
    def test_firmware_digest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p,_=self.make_image(d)
            with self.assertRaisesRegex(t.TriageError,"SHA256 mismatch"):
                t.image_metadata(p)
    def test_pinned_arm64_header(self):
        with tempfile.TemporaryDirectory() as d:
            p,digest=self.make_image(d)
            with patch.object(t,"STOCK_SHA256",digest):
                r=t.image_metadata(p)
            self.assertEqual(r["textOffset"],"0x80000")
            self.assertEqual(r["arm64ImageMagic"],"41524d64")
            self.assertTrue(r["factoryBinaryUnmodified"])
    def test_header_non_arm64_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p,_=self.make_image(d)
            raw=bytearray(p.read_bytes());raw[0x38]=0
            p.write_bytes(raw)
            with patch.object(t,"STOCK_SHA256",hashlib.sha256(raw).hexdigest()):
                with self.assertRaisesRegex(t.TriageError,"ARM64 Image header"):
                    t.image_metadata(p)
    def test_timeout_does_not_claim_boot(self):
        r=t.interpret("","", "TIMEOUT")
        self.assertFalse(r["linuxEarlyBootBannerSeen"])
        self.assertFalse(r["kernelEntryProven"])
        self.assertFalse(r["hxl1KernelBootedToUserspace"])
        self.assertFalse(r["rootOrKernelSuProven"])
    def test_generic_instruction_blocks_not_kernel_proof(self):
        r=t.interpret("", "IN:\n0x40000000: insn\n","TIMEOUT")
        self.assertTrue(r["qemuTranslatedInstructionBlocksSeen"])
        self.assertFalse(r["kernelEntryProven"])
        self.assertFalse(r["sourceFaithfulGuestEstablished"])
    def test_executable_emulator_stub(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p,digest=self.make_image(d)
            fake=root/"fake-qemu"
            fake.write_text("#!/usr/bin/env python3\n"
                            "import pathlib,sys\n"
                            "if '--version' in sys.argv:\n"
                            " print('QEMU emulator version TEST');sys.exit(0)\n"
                            "path=pathlib.Path(sys.argv[sys.argv.index('-D')+1])\n"
                            "path.write_text('IN:\\n0x40000000: mov x0, x0\\n')\n"
                            "print('firmware test harness only')\n")
            fake.chmod(0o755)
            out=root/"out"
            with patch.object(t,"STOCK_SHA256",digest):
                report=t.bounded_probe(p,str(fake),out,3)
            self.assertEqual(report["evidence"]["outcome"],"EXITED")
            self.assertTrue(report["evidence"]["qemuTranslatedInstructionBlocksSeen"])
            self.assertFalse(report["evidence"]["kernelEntryProven"])
            self.assertTrue((out/"report.json").is_file())
            with patch.object(t,"STOCK_SHA256",digest):
                with self.assertRaisesRegex(t.TriageError,"already exists"):
                    t.bounded_probe(p,str(fake),out,3)
    def test_input_does_not_allow_output_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            p,digest=self.make_image(d)
            with self.assertRaises(t.TriageError):
                t.bounded_probe(p, "qemu-system-aarch64", Path(d), 3)
    def test_timeout_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            p,_=self.make_image(d)
            with self.assertRaisesRegex(t.TriageError,"3 through 60"):
                t.bounded_probe(p,"qemu-system-aarch64",Path(d)/"out",65)

if __name__=="__main__":
    unittest.main()
