"""Synthetic tests: independent stock-Image opcode witnesses and honest offset ledger."""
from __future__ import annotations
import hashlib
import json
import zipfile
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
            m.factory_words(synthetic_factory_image()[:0xc7d00])

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
                 patch.object(m.prior,"attest",return_value={"witnessCount":31}), \
                 patch.object(m,"verify_rea_dossiers",return_value={"remove_waiter":{"actualGhidraRecordsIndependentlyChecked":True}}):
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

    def evidence_archives(self,root):
        slices=root/"slices.zip"
        rea=root/"rea.zip"
        entries={}
        with zipfile.ZipFile(slices,"w") as code, zipfile.ZipFile(rea,"w") as extracted:
            for name,(addr,length,_,_) in m.prior.ELFS.items():
                if name not in ("remove_waiter","rt_mutex_start_proxy_lock"):continue
            records={}
            for name,addr in (("remove_waiter","0x100"),("rt_mutex_start_proxy_lock","0x200"),("futex_lock_pi","0x300")):
                address=addr[2:]
                data=("synthetic-"+name).encode()
                digest=hashlib.sha256(data).hexdigest()
                code.writestr("isolated-"+name+"-"+address+".elf",data)
                doc={"operation":"read_function_instructions","provider":{"id":"ghidra"},
                     "subject":{"digest":{"sha256":digest}},
                     "parameters":{"procedure":"0x10000"},
                     "normalized_result":{"instructions":["0x10000: nop","0x10004: ret"]}}
                extracted.writestr("rea-slice-"+name+"-"+address+".json",json.dumps(doc))
                records[name]={"symbolVA":addr,"reaInstructionCount":2,
                               "isolatedCode":{"sha256":digest,"stockBytes":16}}
            manifest={"status":"STATIC_CODE_CORRELATION_ONLY",
                      "firmware":"G986U1UESCHXL1",
                      "originalKernelSha256":m.prior.ORIGINAL_IMAGE_SHA,
                      "functions":records}
            extracted.writestr("stage3-rea-correlation.json",json.dumps(manifest))
        return slices,rea

    def test_all_three_bounded_original_ghidra_dossiers_checked(self):
        with tempfile.TemporaryDirectory() as d:
            slices,rea=self.evidence_archives(Path(d))
            docs=m.verify_rea_dossiers(slices,rea)
            self.assertEqual(len(docs),3)
            self.assertEqual(sum(x["ghidraInstructionCount"] for x in docs.values()),6)
            self.assertFalse(any(x["sourceToCMemberFullDefUseCertified"] for x in docs.values()))

    def test_wrong_rea_ghidra_instruction_address_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);slices,rea=self.evidence_archives(root)
            bad=root/"bad.zip"
            with zipfile.ZipFile(rea) as reader, zipfile.ZipFile(bad,"w") as writer:
                for name in reader.namelist():
                    body=reader.read(name)
                    if name.startswith("rea-slice-remove_waiter"):
                        obj=json.loads(body)
                        obj["normalized_result"]["instructions"][0]="0x30000: nop"
                        body=json.dumps(obj).encode()
                    writer.writestr(name,body)
            with self.assertRaisesRegex(m.ProofError,"escaped"):
                m.verify_rea_dossiers(slices,bad)

    def test_rea_evidence_wrong_provider_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);slices,rea=self.evidence_archives(root)
            bad=root/"bad.zip"
            with zipfile.ZipFile(rea) as reader, zipfile.ZipFile(bad,"w") as writer:
                for name in reader.namelist():
                    body=reader.read(name)
                    if name.startswith("rea-slice-futex_lock_pi"):
                        obj=json.loads(body)
                        obj["provider"]["id"]="invented"
                        body=json.dumps(obj).encode()
                    writer.writestr(name,body)
            with self.assertRaisesRegex(m.ProofError,"provenance"):
                m.verify_rea_dossiers(slices,bad)

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
