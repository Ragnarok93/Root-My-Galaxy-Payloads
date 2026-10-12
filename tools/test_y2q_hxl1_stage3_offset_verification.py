"""Synthetic tests: independent stock-Image opcode witnesses and honest offset ledger."""
from __future__ import annotations
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_stage3_offset_verification as m

def synthetic_factory_image():
    data=bytearray(0x140000)
    data[0x38:0x3c]=b"ARM\x64"
    for name,(start,length,_,_) in m.prior.ELFS.items():
        base=int(start,16)-m.original.TEXT_VA
        for offset,word in m.prior.WORDS[name].items():
            data[base+offset:base+offset+4]=bytes.fromhex(word)[::-1]
    return bytes(data)

class Stage3OffsetVerifierTests(unittest.TestCase):
    def test_all_31_factory_instruction_words_verified(self):
        actual=m.factory_words(synthetic_factory_image())
        self.assertEqual(len(actual),31)
        self.assertTrue(all(x["originalImageWordVerified"] for x in actual))
        self.assertFalse(any(x["originalCFieldIdentityProven"] for x in actual))

    def test_changed_original_opcode_fails_closed(self):
        source=bytearray(synthetic_factory_image())
        loc=int(m.prior.ELFS["remove_waiter"][0],16)-m.original.TEXT_VA+0x28
        source[loc]^=1
        with self.assertRaisesRegex(m.ProofError,"factory original word differs"):
            m.factory_words(bytes(source))

    def test_wrong_kernel_image_header_refused(self):
        raw=bytearray(synthetic_factory_image());raw[0x38]=0
        with self.assertRaisesRegex(m.ProofError,"ARM64 Image"):
            m.factory_words(bytes(raw))

    def test_truncated_stock_image_is_refused(self):
        with self.assertRaisesRegex(m.ProofError,"code bounds invalid"):
            m.factory_words(synthetic_factory_image()[:0xc8000])

    def test_separate_clang10_object_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            o=root/"kernel/locking/rtmutex.o"
            o.parent.mkdir(parents=True)
            header=bytearray(64)
            header[:6]=b"\x7fELF\x02\x01"
            header[16:18]=(1).to_bytes(2,"little")
            header[18:20]=(183).to_bytes(2,"little")
            o.write_bytes(header)
            with patch.object(m.shutil,"which",return_value=None):
                files=m.compiled_objects(root)
            self.assertEqual(len(files),1)
            self.assertEqual(files[0]["sha256"],m.port.sha256(o))
            self.assertTrue(files[0]["aarch64ET_REL"])
            self.assertFalse(files[0]["originalOEMObject"])

    def test_wrong_architecture_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);o=root/"kernel/futex.o";o.parent.mkdir()
            hdr=bytearray(64);hdr[:6]=b"\x7fELF\x02\x01"
            hdr[16:18]=(1).to_bytes(2,"little")
            hdr[18:20]=(62).to_bytes(2,"little")
            o.write_bytes(hdr)
            files=m.compiled_objects(root)
            self.assertEqual(len(files),1)
            self.assertFalse(files[0]["aarch64ET_REL"])

    def test_missing_build_tree_yields_no_fake_objects(self):
        with tempfile.TemporaryDirectory() as d:
            result=m.compiled_objects(Path(d)/"missing")
            self.assertEqual(result,[])

    def test_symlinked_build_tree_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);alias=root/"alias";alias.symlink_to(root,target_is_directory=True)
            self.assertEqual(m.compiled_objects(alias),[])

    def test_archived_rea_missing_does_not_claim_success(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);factory=root/"stock";factory.mkdir()
            (factory/"kernel.bin").write_bytes(synthetic_factory_image())
            report={"originalReport":{"sha256":"a"*64},"aarch64ObjectCount":0}
            hashes={"kernel.bin":{"state":"VERIFIED"},"config.gz":{"state":"VERIFIED"}}
            with patch.object(m.port,"check_factory_inputs",return_value=hashes), \
                 patch.object(m.checkpoint,"audit",return_value=report):
                result=m.audit(factory,root,root,root/"build",
                               root/"not-found-slices.zip",root/"not-found-rea.zip")
            self.assertEqual(result["stockOpcodeWitnessesVerified"],31)
            self.assertEqual(result["factoryMemberOffsetsVerified"],0)
            self.assertFalse(result["stage3Complete"])
            self.assertFalse(result["runtimeRootOrKernelSuProven"])
            self.assertEqual(result["reaEvidence"]["state"],"OWNER_REA_ARCHIVES_UNAVAILABLE")
            self.assertEqual(len(result["memberCandidates"]),13)
            self.assertIn("UNVERIFIED",m.markdown(result))

    def test_archived_rea_accepted_only_if_reviewer_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);factory=root/"stock";factory.mkdir()
            (factory/"kernel.bin").write_bytes(synthetic_factory_image())
            sl=root/"slices.zip";sl.write_text("fake")
            rea=root/"rea.zip";rea.write_text("fake")
            hashes={"kernel.bin":{"state":"VERIFIED"},"config.gz":{"state":"VERIFIED"}}
            report={"originalReport":{"sha256":"a"*64},"aarch64ObjectCount":0}
            with patch.object(m.port,"check_factory_inputs",return_value=hashes), \
                 patch.object(m.checkpoint,"audit",return_value=report), \
                 patch.object(m.prior,"attest",return_value={"witnessCount":31}):
                got=m.audit(factory,root,root,root/"build",sl,rea)
            self.assertIn("ATTESTED",got["reaEvidence"]["state"])
            self.assertFalse(got["reaEvidence"]["memberSpecificFactoryDefUseProven"])

    def test_wrong_attestation_witness_count_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fac=root/"stock";fac.mkdir()
            (fac/"kernel.bin").write_bytes(synthetic_factory_image())
            a=root/"slices.zip";a.touch()
            b=root/"rea.zip";b.touch()
            fake={"kernel.bin":{"state":"VERIFIED"},"config.gz":{"state":"VERIFIED"}}
            with patch.object(m.port,"check_factory_inputs",return_value=fake), \
                 patch.object(m.checkpoint,"audit",return_value={"originalReport":{"sha256":"a"*64},"aarch64ObjectCount":0}), \
                 patch.object(m.prior,"attest",return_value={"witnessCount":30}):
                with self.assertRaisesRegex(m.ProofError,"witness mismatch"):
                    m.audit(fac,root,root,root/"build",a,b)

    def test_script_help_from_isolated_dir(self):
        with tempfile.TemporaryDirectory() as d:
            run=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                cwd=d,capture_output=True,text=True,timeout=15)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn("--object-root",run.stdout)
            self.assertIn("--comparison",run.stdout)

    def test_no_device_operations_or_original_writes(self):
        src=Path(m.__file__).read_text()
        for bad in ("adb shell","fastboot flash","qemu-system-aarch64","git reset",
                    "KernelSU install","target.h\"","git push"):
            self.assertNotIn(bad,src)
        self.assertIn("factory_words(raw)",src)

if __name__=="__main__":
    unittest.main()
