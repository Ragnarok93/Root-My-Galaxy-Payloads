"""Host-only regression tests for reusing the original failed HXL1 ZIP inputs."""
from __future__ import annotations
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_porting_bundle_repair as m
from tools import y2q_research_toolchain as t
from tools.test_y2q_research_toolchain import research_candidate,fake_elf

def factory_integrity():
    return {
        "kernel.bin":{"state":"VERIFIED","actualSha256":m.port.PINNED_KERNEL,
                      "expectedSha256":m.port.PINNED_KERNEL},
        "config.gz":{"state":"VERIFIED","actualSha256":m.port.PINNED_CONFIG,
                     "expectedSha256":m.port.PINNED_CONFIG},
    }

@contextmanager
def setup_run(library_name=m.LEGACY):
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        artifacts=root/"s20-artifacts"
        research=artifacts/"hxl1-research"
        folder=research/"port-automation-synthetic"
        folder.mkdir(parents=True)
        candidate=research_candidate()
        (folder/m.SCAN).write_text(json.dumps(candidate))
        lib=folder/library_name
        lib.write_bytes(fake_elf())
        metadata={
            "kind":t.RESEARCH_KIND,"device":candidate["device"],
            "deploymentBlocked":True,"publishInSupportFeed":False,
            "executableExploit":False,"rootVerified":False,
            "kernelWriteCapability":False,"moduleLoadCapability":False,
            "scanReportSha256":m.port.sha256(folder/m.SCAN),
            "payload":{"file":library_name,
                       "sha256":m.port.sha256(lib),
                       "sizeBytes":lib.stat().st_size},
        }
        (folder/m.MANIFEST).write_text(json.dumps(metadata))
        prior={
            "runId":folder.name,
            "target":"SM-G986U1/G986U1UESCHXL1",
            "inputIntegrity":factory_integrity(),
            "steps":[
                {"id":"05_source_candidate","status":"PASS",
                 "sha256":m.port.sha256(folder/m.SCAN)},
                {"id":"06_build_identity_only","status":"PASS",
                 "sha256":m.port.sha256(lib)},
                {"id":"06_bundle_identity_only","status":"FAIL"}],
        }
        (folder/"port-automation.json").write_text(json.dumps(prior))
        yield artifacts,folder

class BundleRepairTests(unittest.TestCase):
    def inspect(self,folder,artifacts):
        with patch.object(m.port,"check_factory_inputs",return_value=factory_integrity()):
            return m.validate_run(folder,artifacts)

    def recover(self,folder,artifacts):
        with patch.object(m.port,"check_factory_inputs",return_value=factory_integrity()):
            return m.repair(folder,artifacts)

    def test_legacy_original_owner_bundle_recovers_without_rerunning_scans(self):
        with setup_run() as (artifacts,folder):
            orig=(folder/"port-automation.json").read_bytes()
            result=self.recover(folder,artifacts)
            self.assertEqual(result["status"],
                             "PREVIOUS_HXL1_DIAGNOSTIC_BUNDLE_RECOVERED")
            self.assertEqual(result["sourceLibraryName"],m.LEGACY)
            self.assertEqual(orig,(folder/"port-automation.json").read_bytes())
            self.assertTrue((folder/m.RECOVERED).is_file())
            self.assertTrue((folder/m.REPORT).is_file())
            self.assertFalse(result["deployableRootPayload"])
            self.assertFalse(result["deviceModified"])

    def test_canonical_library_recovers_too(self):
        with setup_run(m.CANONICAL) as (artifacts,folder):
            result=self.recover(folder,artifacts)
            self.assertEqual(result["sourceLibraryName"],m.CANONICAL)

    def test_mismatched_factory_hash_cannot_recover(self):
        with setup_run() as (artifacts,folder):
            wrong=factory_integrity()
            wrong["kernel.bin"]["state"]="SHA256_MISMATCH"
            with patch.object(m.port,"check_factory_inputs",return_value=wrong):
                with self.assertRaisesRegex(m.RepairError,"hashes not verified"):
                    m.validate_run(folder,artifacts)

    def test_prior_report_scan_hash_must_match(self):
        with setup_run() as (artifacts,folder):
            (folder/m.SCAN).write_text("{}")
            with self.assertRaisesRegex(m.RepairError,"source scan"):
                self.inspect(folder,artifacts)

    def test_modified_library_refused(self):
        with setup_run() as (artifacts,folder):
            (folder/m.LEGACY).write_bytes(fake_elf()+b"mutated")
            with self.assertRaisesRegex(m.RepairError,"No unique prior"):
                self.inspect(folder,artifacts)

    def test_mismatched_manifest_name_refused(self):
        with setup_run() as (artifacts,folder):
            data=json.loads((folder/m.MANIFEST).read_text())
            data["payload"]["file"]=m.CANONICAL
            (folder/m.MANIFEST).write_text(json.dumps(data))
            with self.assertRaisesRegex(m.RepairError,"Manifest does not match"):
                self.inspect(folder,artifacts)

    def test_unverified_prior_scan_or_build_refused(self):
        with setup_run() as (artifacts,folder):
            path=folder/"port-automation.json"
            previous=json.loads(path.read_text())
            previous["steps"][1]["status"]="FAIL"
            path.write_text(json.dumps(previous))
            with self.assertRaisesRegex(m.RepairError,"only scan/build PASS"):
                self.inspect(folder,artifacts)

    def test_recovery_is_exclusive_and_idempotently_refuses_rewrite(self):
        with setup_run() as (artifacts,folder):
            self.recover(folder,artifacts)
            with self.assertRaisesRegex(m.RepairError,"already exists"):
                self.inspect(folder,artifacts)

    def test_bad_run_parent_refused(self):
        with setup_run() as (artifacts,folder):
            with self.assertRaisesRegex(m.RepairError,"non-HXL1 run"):
                self.inspect(folder.parent,artifacts)

    def test_unsafe_source_symlink_refused(self):
        with setup_run() as (artifacts,folder):
            scan=folder/m.SCAN
            replacement=folder/"stored-scan.json"
            scan.rename(replacement)
            scan.symlink_to(replacement)
            with self.assertRaisesRegex(m.RepairError,"source scan"):
                self.inspect(folder,artifacts)

    def verify_previous(self,folder,artifacts):
        with patch.object(m.port,"check_factory_inputs",return_value=factory_integrity()):
            return m.verify_existing(folder,artifacts)

    def test_existing_recovery_is_verified_idempotently_without_writes(self):
        with setup_run() as (artifacts,folder):
            self.recover(folder,artifacts)
            tracked=[folder/m.RECOVERED,folder/m.REPORT,
                     folder/"port-automation.json",folder/m.MANIFEST]
            original={p.name:p.read_bytes() for p in tracked}
            result=self.verify_previous(folder,artifacts)
            second=self.verify_previous(folder,artifacts)
            self.assertEqual(result,second)
            self.assertEqual(result["status"],
                             "EXISTING_HXL1_DIAGNOSTIC_BUNDLE_VERIFIED")
            self.assertTrue(result["archiveMatchesOriginalInputs"])
            self.assertFalse(result["rootOrKernelSuVerified"])
            self.assertEqual(original,{p.name:p.read_bytes() for p in tracked})

    def test_existing_canonical_bundle_is_also_verified(self):
        with setup_run(m.CANONICAL) as (artifacts,folder):
            self.recover(folder,artifacts)
            result=self.verify_previous(folder,artifacts)
            self.assertEqual(result["status"],
                             "EXISTING_HXL1_DIAGNOSTIC_BUNDLE_VERIFIED")

    def test_only_zip_existing_is_reported_partial_not_overwritten(self):
        with setup_run() as (artifacts,folder):
            (folder/m.RECOVERED).write_bytes(b"prior partial output")
            with self.assertRaisesRegex(m.RepairError,"Partial recovery"):
                self.verify_previous(folder,artifacts)
            self.assertEqual((folder/m.RECOVERED).read_bytes(),
                             b"prior partial output")

    def test_only_report_existing_is_reported_partial(self):
        with setup_run() as (artifacts,folder):
            (folder/m.REPORT).write_text("{}")
            with self.assertRaisesRegex(m.RepairError,"Partial recovery"):
                self.verify_previous(folder,artifacts)
            self.assertEqual((folder/m.REPORT).read_text(),"{}")

    def test_no_recovered_outputs_fails_verification_without_writing(self):
        with setup_run() as (artifacts,folder):
            with self.assertRaisesRegex(m.RepairError,"No existing recovery"):
                self.verify_previous(folder,artifacts)
            self.assertFalse((folder/m.RECOVERED).exists())

    def test_existing_report_hash_mismatch_refused(self):
        with setup_run() as (artifacts,folder):
            self.recover(folder,artifacts)
            report=folder/m.REPORT
            saved=json.loads(report.read_text())
            saved["recoveredZipSha256"]="0"*64
            report.write_text(json.dumps(saved))
            with self.assertRaisesRegex(m.RepairError,"recoveredZipSha256"):
                self.verify_previous(folder,artifacts)

    def test_existing_zip_content_tamper_refused(self):
        with setup_run() as (artifacts,folder):
            self.recover(folder,artifacts)
            zipfile=folder/m.RECOVERED
            zipfile.write_bytes(zipfile.read_bytes()+b"modified")
            with self.assertRaisesRegex(m.RepairError,"recoveredZipSha256"):
                self.verify_previous(folder,artifacts)

    def test_existing_archive_symlink_refused(self):
        with setup_run() as (artifacts,folder):
            self.recover(folder,artifacts)
            z=folder/m.RECOVERED
            preserved=folder/"saved-bundle.zip"
            z.rename(preserved)
            z.symlink_to(preserved)
            with self.assertRaisesRegex(m.RepairError,"symlinks"):
                self.verify_previous(folder,artifacts)

    def test_verify_existing_preserves_original_root_denial(self):
        with setup_run() as (artifacts,folder):
            self.recover(folder,artifacts)
            data=json.loads((folder/m.MANIFEST).read_text())
            data["rootVerified"]=True
            (folder/m.MANIFEST).write_text(json.dumps(data))
            with self.assertRaisesRegex(m.RepairError,"Manifest does not match|inert"):
                self.verify_previous(folder,artifacts)

    def test_verify_existing_option_is_read_only_and_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            proc=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                                cwd=temp,text=True,capture_output=True,timeout=15)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertIn("--verify-existing",proc.stdout)
            bad=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),
                                "--run-dir",str(Path(temp)/"fake"),
                                "--verify-existing","--preflight-only"],
                               capture_output=True,text=True,timeout=15)
            self.assertNotEqual(bad.returncode,0)
            self.assertIn("not allowed",bad.stderr)

    def test_help_without_current_working_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            proc=subprocess.run([
                sys.executable,"-I",str(Path(m.__file__)),"--help"],
                cwd=temp,capture_output=True,text=True,timeout=15)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertIn("--run-dir",proc.stdout)
            self.assertIn("--preflight-only",proc.stdout)

    def test_no_phone_flash_qemu_or_original_report_update(self):
        text=Path(m.__file__).read_text()
        for unsafe in ("adb shell","fastboot flash","qemu-system-aarch64",
                       "git reset","requests.post","os.system"):
            self.assertNotIn(unsafe,text)
        self.assertIn("command_bundle",text)
        self.assertNotIn('ctx["original"].write_text',text)

if __name__=="__main__":
    unittest.main()
