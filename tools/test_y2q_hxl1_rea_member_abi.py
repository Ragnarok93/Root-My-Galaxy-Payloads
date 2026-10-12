"""REA/Ghidra original-factory HXL1 ABI dataflow runner regression tests."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import y2q_hxl1_rea_member_abi as m

def fixture_abi():
    fields=[]
    for ty,items in m.prior.FIELDS.items():
        for field,offset in items.items():
            fields.append({"type":ty,"member":field,"comparisonOffset":offset,
                           "staticGhidraChainMatched":True,
                           "factoryCMemberIdentityCertified":False})
    return {"savedFactoryVerifierSha256":"b"*64,
            "registerFlowWorklist":{"candidates":fields,"matchedStaticChains":9}}

def fake_decompiler(sha):
    return {
      "operation":"analyze_function","provider":{"id":"ghidra"},
      "subject":{"digest":{"sha256":sha}},
      "parameters":{"procedure":"0x10000"},"evidence_id":"ev_abc123",
      "normalized_result":{
         "procedure":{"address":"0x10000","body":{
             "available":True,"ranges":[{"start":"0x10000","end":"0x10120"}]}},
         "pseudocode":"void FUN_00010000(long arg) { return; }",
         "native_value_flow":{"available":True,"truncated":False,
                              "operations":[{"opcode":"LOAD","address":"0x1003c"}]}
      }
    }

def fake_saved_dossiers():
    return {name:{"sourceElfSha256":hashlib.sha256(name.encode()).hexdigest(),
                  "originalStockByteAttestation":{"symbolVA":"0x"+format(0xffffff8008147db4+i*4,"x")}}
            for i,name in enumerate(m.FUNCTIONS)}

class AbiViaRealGhidraTests(unittest.TestCase):
    def test_valid_ghidra_function_and_highfunction_metadata(self):
        doc=m.check_function_evidence(fake_decompiler("abc"),"remove_waiter","abc")
        self.assertEqual(doc["state"],"GHIDRA_HIGHFUNCTION_AVAILABLE")
        self.assertEqual(doc["reportedPcodeOperationCount"],1)
        self.assertEqual(doc["ghidraFieldOffsetsCertified"],0)

    def test_available_pcode_is_not_equivalent_to_factory_field_abi(self):
        doc=m.check_function_evidence(fake_decompiler("abc"),"remove_waiter","abc")
        self.assertFalse(doc["fullBranchSensitiveSourceToCMemberMapping"])

    def test_absent_pcode_does_not_claim_full_dataflow(self):
        e=fake_decompiler("abc")
        e["normalized_result"]["native_value_flow"]["available"]=False
        self.assertEqual(m.check_function_evidence(e,"remove_waiter","abc")["state"],
                         "GHIDRA_ANALYSIS_INCOMPLETE")

    def test_truncated_pcode_does_not_claim_complete(self):
        e=fake_decompiler("abc")
        e["normalized_result"]["native_value_flow"]["truncated"]=True
        self.assertEqual(m.check_function_evidence(e,"remove_waiter","abc")["state"],
                         "GHIDRA_ANALYSIS_INCOMPLETE")

    def test_wrong_subject_digest_refused(self):
        with self.assertRaisesRegex(m.AbiError,"source/function identity"):
            m.check_function_evidence(fake_decompiler("wrong"),"remove_waiter","abc")

    def test_bad_ghidra_provider_refused(self):
        doc=fake_decompiler("abc")
        doc["provider"]["id"]="not-ghidra"
        with self.assertRaisesRegex(m.AbiError,"provider"):
            m.check_function_evidence(doc,"remove_waiter","abc")

    def test_wrong_function_owner_refused(self):
        doc=fake_decompiler("abc")
        doc["normalized_result"]["procedure"]["address"]="0x10008"
        with self.assertRaisesRegex(m.AbiError,"entry changed"):
            m.check_function_evidence(doc,"remove_waiter","abc")

    def test_no_function_body_refused(self):
        doc=fake_decompiler("abc")
        doc["normalized_result"]["procedure"]["body"]["available"]=False
        with self.assertRaisesRegex(m.AbiError,"body"):
            m.check_function_evidence(doc,"remove_waiter","abc")

    def test_not_run_is_not_ghidra_evidence(self):
        self.assertEqual(m.check_function_evidence(None,"futex_lock_pi","abc")["state"],
                         "NOT_EXECUTED")

    def test_summary_honors_all_thirteen_candidates_but_zero_certification(self):
        f=[{"name":name,"state":"GHIDRA_HIGHFUNCTION_AVAILABLE"} for name in m.FUNCTIONS]
        r=m.stage3_summary(fixture_abi(),f)
        self.assertEqual(r["staticRegisterCandidates"],13)
        self.assertEqual(r["factoryStructMemberOffsetsVerified"],0)
        self.assertFalse(r["completeFactoryAbiVerified"])
        self.assertFalse(r["stage3Complete"])
        self.assertFalse(r["rootOrKernelSuVerified"])

    def test_modified_slice_refused_against_verified_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"slices.zip"
            records=fake_saved_dossiers()
            with zipfile.ZipFile(p,"w") as z:
                for name in m.FUNCTIONS:
                    r=records[name]
                    va=r["originalStockByteAttestation"]["symbolVA"][2:]
                    z.writestr("isolated-"+name+"-"+va+".elf",name.encode())
            good=m.bounded_slices(p,records)
            self.assertEqual(len(good),3)
            with zipfile.ZipFile(p,"w") as z:
                for name in m.FUNCTIONS:
                    r=records[name]
                    va=r["originalStockByteAttestation"]["symbolVA"][2:]
                    z.writestr("isolated-"+name+"-"+va+".elf",b"tampered")
            with self.assertRaisesRegex(m.AbiError,"hash changed"):
                m.bounded_slices(p,records)

    def test_execute_only_writes_into_new_directory_after_preverification(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            rea=root/"rea.mjs"
            rea.write_text("// stub real entrypoint is only used as a presence check")
            output=root/"fresh"
            for name in m.FUNCTIONS:
                self.assertFalse((output/"subjects"/(name+".elf")).exists())
            (root/"rea.zip").write_bytes(b"synthetic rea evidence source")
            (root/"slice.zip").write_bytes(b"synthetic slice input")
            originals=fake_saved_dossiers()
            blobs={name:(name.encode(),hashlib.sha256(name.encode()).hexdigest())
                   for name in m.FUNCTIONS}
            class FakeRunner:
                def __init__(self,*args,**kwargs):
                    self.planned=[]
                def obtain(self,target,argv,dest,**kwargs):
                    self.planned.append(argv)
                    self_args=argv
                    assert self_args[0]=="function" and self_args[2]=="0x10000"
                    assert target.path.read_bytes()==target.name.encode()
                    return fake_decompiler(target.sha256)
            with patch.object(m,"verify_source_and_archives",
                              return_value=({},originals,fixture_abi())), \
                 patch.object(m,"bounded_slices",return_value=blobs), \
                 patch.object(m,"Runner",FakeRunner):
                out=m.run(root/"saved.json",root/"factory.bin",root/"source",
                          root/"slice.zip",root/"rea.zip",rea,output,execute=True)
            self.assertEqual(len(out["ghidraFunctions"]),3)
            self.assertTrue((output/"hxl1-ghidra-member-abi.json").exists())
            self.assertTrue((output/"subjects/remove_waiter.elf").exists())
            self.assertFalse(out["completeFactoryAbiVerified"])

    def test_existing_report_directory_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)
            with self.assertRaisesRegex(m.AbiError,"new output directory"):
                m.validate_output(folder,[])

    def test_disallow_output_inside_repository(self):
        path=m.port.REPO/"fake-new-folder"
        with self.assertRaisesRegex(m.AbiError,"inside original"):
            m.validate_output(path,[m.port.REPO])

    def test_ghidra_runner_never_contains_phone_or_root_ops(self):
        s=Path(m.__file__).read_text()
        for forbidden in ("adb shell","fastboot flash","qemu-system-aarch64",
                          "target_h.write", "os.system(", "git push"):
            self.assertNotIn(forbidden,s)
        self.assertIn('["function",str(subject),"0x10000"]',s)
        self.assertIn("originalStage3ReportSha256",s)

    def test_wsl_runner_invokes_real_ghidra_and_preserves_factory_report(self):
        script=Path(m.__file__).parent/"run_y2q_hxl1_rea_member_abi.sh"
        body=script.read_text()
        p=subprocess.run(["bash","-n",str(script)],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn("y2q_hxl1_rea_member_abi.py",body)
        self.assertIn("--execute",body)
        self.assertIn("--verified-stage3-report",body)
        for forbidden in ("rm -rf","git reset","adb shell","fastboot","qemu-system"):
            self.assertNotIn(forbidden,body)

    def test_executable_help_without_local_ghidra(self):
        with tempfile.TemporaryDirectory() as temp:
            p=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                             cwd=temp,capture_output=True,text=True,timeout=15)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn("--execute",p.stdout)
            self.assertIn("--verified-stage3-report",p.stdout)
            self.assertIn("--timeout",p.stdout)

if __name__=="__main__":
    unittest.main()
