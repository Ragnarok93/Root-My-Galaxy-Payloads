"""Synthetic fail-closed HXL1 Clang10 comparison evidence inventory tests."""
from __future__ import annotations
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_clang10_checkpoint as m

@contextmanager
def original_fixture():
    with tempfile.TemporaryDirectory() as temp:
        factory=Path(temp)/"s20-artifacts"
        comparison=factory/"hxl1-research/clang10-abi-comparison"
        comparison.mkdir(parents=True)
        report=comparison/"factory-displacement-comparison.json"
        report.write_text(json.dumps({
            "sample":"Synthetic only: never factory-hardware validation",
            "instructionCount":31,"candidateFieldCount":13,
        }))
        obj=comparison/"kernel"/"locking"/"rtmutex.o"
        obj.parent.mkdir(parents=True)
        header=bytearray(64)
        header[:6]=b"\x7fELF\x02\x01"
        header[16:18]=(1).to_bytes(2,"little")
        header[18:20]=(183).to_bytes(2,"little")
        obj.write_bytes(header)
        yield factory,comparison,report,obj

def verified_hashes():
    return {name:{"state":"VERIFIED","expectedSha256":value,
                   "actualSha256":value} for name,value in (
        ("kernel.bin",m.port.PINNED_KERNEL),
        ("config.gz",m.port.PINNED_CONFIG))}

class Clang10InventoryTests(unittest.TestCase):
    def audit(self,factory,comparison):
        with patch.object(m.port,"check_factory_inputs",return_value=verified_hashes()):
            return m.audit(factory,comparison)

    def test_only_attests_input_hashes_and_object_format(self):
        with original_fixture() as (f,d,report,obj):
            result=self.audit(f,d)
            self.assertEqual(result["originalReport"]["sha256"],m.port.sha256(report))
            self.assertEqual(result["aarch64ObjectCount"],1)
            self.assertEqual(result["aarch64ObjectInventory"][0]["sha256"],m.port.sha256(obj))
            for claim in ("factoryCompilerAuthenticated","factoryAbiAuthenticated",
                          "stage3PortingGatePassed","runtimeGhostlockPrimitiveVerified",
                          "rootVerified","kernelSuLoaded","phoneModified",
                          "candidate31FactoryInstructionsVerifiedByThisTool"):
                v=result["originalReport"].get(claim,result.get(claim))
                self.assertIs(v,False,claim)
            self.assertEqual(result["originalReport"]["contentInterpretation"],
                             "NOT_INDEPENDENTLY_VALIDATED")

    def test_original_image_wrong_digest_fails_closed(self):
        with original_fixture() as (f,d,*_):
            data=verified_hashes()
            data["kernel.bin"]["state"]="SHA256_MISMATCH"
            with patch.object(m.port,"check_factory_inputs",return_value=data):
                with self.assertRaisesRegex(m.CheckpointError,"hash"):
                    m.audit(f,d)

    def test_missing_factory_digest_refused(self):
        with original_fixture() as (f,d,*_):
            with patch.object(m.port,"check_factory_inputs",return_value={}):
                with self.assertRaises(m.CheckpointError):
                    m.audit(f,d)

    def test_missing_comparison_report_refused(self):
        with original_fixture() as (f,d,r,*_):
            r.unlink()
            with self.assertRaisesRegex(m.CheckpointError,"Missing"):
                self.audit(f,d)

    def test_invalid_json_is_not_accepted(self):
        with original_fixture() as (f,d,r,*_):
            r.write_text('not-json')
            with self.assertRaises(ValueError):
                self.audit(f,d)

    def test_json_list_not_accepted_as_report(self):
        with original_fixture() as (f,d,r,*_):
            r.write_text('[]')
            with self.assertRaisesRegex(m.CheckpointError,"JSON object"):
                self.audit(f,d)

    def test_large_or_unusual_report_keys_refused(self):
        with original_fixture() as (f,d,r,*_):
            r.write_text(json.dumps({"odd\nfield":1}))
            with self.assertRaisesRegex(m.CheckpointError,"Invalid"):
                self.audit(f,d)

    def test_comparison_dir_symlink_refused(self):
        with original_fixture() as (f,d,r,*_):
            alias=d.parent/"linked-compare"
            alias.symlink_to(d,target_is_directory=True)
            with self.assertRaisesRegex(m.CheckpointError,"symlink"):
                self.audit(f,alias)

    def test_original_json_symlink_refused(self):
        with original_fixture() as (f,d,r,*_):
            old=d/"saved-comparison.json"
            r.rename(old)
            r.symlink_to(old)
            with self.assertRaisesRegex(m.CheckpointError,"symlink"):
                self.audit(f,d)

    def test_object_symlink_refused(self):
        with original_fixture() as (f,d,r,obj):
            second=obj.with_name("symlink.o")
            second.symlink_to(obj)
            with self.assertRaisesRegex(m.CheckpointError,"Symlinked"):
                self.audit(f,d)

    def test_non_aarch64_objects_do_not_masquerade(self):
        with original_fixture() as (f,d,r,obj):
            raw=bytearray(obj.read_bytes())
            raw[18:20]=(62).to_bytes(2,"little")
            obj.write_bytes(raw)
            result=self.audit(f,d)
            self.assertEqual(result["aarch64ObjectCount"],0)
            self.assertFalse(result["aarch64ObjectInventory"][0]["aarch64RelocatableELF"])

    def test_cli_isolated_help_and_static_no_device_calls(self):
        with tempfile.TemporaryDirectory() as folder:
            run=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                               cwd=folder,capture_output=True,text=True,timeout=12)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn("--comparison",run.stdout)
        code=Path(m.__file__).read_text()
        for forbidden in ("adb shell","fastboot flash","qemu-system-aarch64",
                          "subprocess.run(","os.system(","git push"):
            self.assertNotIn(forbidden,code)

if __name__=="__main__":
    unittest.main()
