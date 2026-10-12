"""Synthetic REA/Ghidra native analysis tests: provenance and zero false ABI claims."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from tools import y2q_hxl1_stage3_rea_native as m

def record(name):
    raw=("stock-copy-"+name).encode()
    return {"label":name,"sha256":hashlib.sha256(raw).hexdigest(),
            "originalSymbolVA":"0x10000",
            "originalStockBytes":len(raw),
            "originalImageBytesIndependentlyVerified":True,
            "originalKernelCodeSha256":hashlib.sha256(raw).hexdigest()}

def document(name="remove_waiter",native=True):
    r=record(name)
    return {"operation":"analyze_function","provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":r["sha256"]},"architecture":"arm64"},
            "parameters":{"procedure":"0x10000"},
            "evidence_id":"ev_fixture_1234",
            "normalized_result":{"procedure":{
                "address":"0x10000","name":name,
                "body":{"available":True,"ranges":[{"start":"0x10000","end":"0x10004"}]}},
                "pseudocode":"int function(void) { return 0; }",
                "native_value_flow":{"available":native,"operations":[]}}}

class TestNativeREA(unittest.TestCase):
    def test_parse_real_ghidra_schema_without_promoting_offset(self):
        r=m.parse_function_analysis(document(),record("remove_waiter"))
        self.assertEqual(r["nativeValueFlowState"],"GHIDRA_HIGH_PCODE_AVAILABLE")
        self.assertTrue(r["functionBodyVerified"])
        self.assertFalse(r["CFieldIdentitiesEstablishedByThisAnalysis"])
        self.assertFalse(r["factoryABIComplete"])
        self.assertEqual(r["provider"],"ghidra")
        self.assertEqual(r["nativePcodeOperationCount"],0)

    def test_no_pcode_reports_unavailable_not_factory_success(self):
        r=m.parse_function_analysis(document(native=False),record("remove_waiter"))
        self.assertEqual(r["nativeValueFlowState"],"GHIDRA_HIGH_PCODE_UNAVAILABLE")
        self.assertFalse(r["CFieldIdentitiesEstablishedByThisAnalysis"])

    def test_wrong_provider_refused(self):
        d=document();d["provider"]["id"]="fake"
        with self.assertRaisesRegex(m.OffsetREAError,"source/function mismatch"):
            m.parse_function_analysis(d,record("remove_waiter"))

    def test_wrong_elf_hash_refused(self):
        d=document();d["subject"]["digest"]["sha256"]="0"*64
        with self.assertRaisesRegex(m.OffsetREAError,"source/function mismatch"):
            m.parse_function_analysis(d,record("remove_waiter"))

    def test_wrong_query_refused(self):
        d=document();d["parameters"]["procedure"]="0x1234"
        with self.assertRaisesRegex(m.OffsetREAError,"source/function mismatch"):
            m.parse_function_analysis(d,record("remove_waiter"))

    def test_ghidra_function_body_must_contain_real_entry(self):
        d=document();d["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x20000","end":"0x20004"}]
        with self.assertRaisesRegex(m.TriageError,"own"):
            m.parse_function_analysis(d,record("remove_waiter"))

    def test_bounded_native_operations(self):
        d=document()
        d["normalized_result"]["native_value_flow"]["operations"]=[{}]*30001
        with self.assertRaisesRegex(m.OffsetREAError,"Unbounded"):
            m.parse_function_analysis(d,record("remove_waiter"))

    def test_extract_correct_archived_original_slices(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);archive=folder/"slices.zip";out=folder/"saved"
            bound={}
            with zipfile.ZipFile(archive,"w") as z:
                for name in m.FUNCTIONS:
                    r=record(name)
                    data=("stock-copy-"+name).encode()
                    z.writestr("isolated-"+name+"-10000.elf",data)
                    bound[name]={"sourceElfSha256":r["sha256"],
                                 "originalStockByteAttestation":{
                                     "symbolVA":"0x10000","stockCodeBytes":len(data),
                                     "originalKernelFunctionBytesSha256":hashlib.sha256(data).hexdigest()}}
            rows=m.extract_slices(archive,bound,out,write=True)
            self.assertEqual(len(rows),3)
            self.assertEqual([x["label"] for x in rows],list(m.FUNCTIONS))
            rows2=m.extract_slices(archive,bound,out,write=True)
            self.assertEqual(rows,rows2)
            self.assertTrue(all(Path(x["providerInput"]).is_file() for x in rows))

    def test_existing_extracted_slice_tamper_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);archive=folder/"slices.zip";out=folder/"saved"
            bound={}
            with zipfile.ZipFile(archive,"w") as z:
                for name in m.FUNCTIONS:
                    data=("stock-copy-"+name).encode()
                    z.writestr("isolated-"+name+"-10000.elf",data)
                    bound[name]={"sourceElfSha256":hashlib.sha256(data).hexdigest(),
                                 "originalStockByteAttestation":{
                                     "symbolVA":"0x10000","stockCodeBytes":len(data)}}
            rows=m.extract_slices(archive,bound,out,write=True)
            Path(rows[0]["providerInput"]).write_bytes(b"changed")
            with self.assertRaisesRegex(m.OffsetREAError,"changed"):
                m.extract_slices(archive,bound,out,write=True)

    def test_plan_has_no_writes_no_rea_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dir=root/"not-created"
            fake=[dict(record(n),providerInput=str(dir/"inputs"/(n+".elf"))) for n in m.FUNCTIONS]
            saved={"registerFlowWorklist":{"matchedStaticChains":9}}
            with patch.object(m,"identity",return_value=({},saved,{})),\
                 patch.object(m,"extract_slices",return_value=fake),\
                 patch.object(m,"Runner") as Runner:
                instance=Runner.return_value
                instance.obtain.return_value=None
                instance.planned=[["node"],["node"],["node"]]
                result=m.run_pipeline(root/"report",root/"image",root/"slices",root/"archive",
                                      root/"src",dir,execute=False,
                                      rea_script=root/"not-installed.mjs",
                                      node="node",timeout=300)
            self.assertFalse(dir.exists())
            self.assertEqual(result["status"],"GHIDRA_QUERIES_PLANNED")
            self.assertEqual(len(result["verifiedFunctions"]),3)
            self.assertEqual(result["factoryMemberOffsetsCertified"],0)
            self.assertFalse(result["stage3Complete"])
            self.assertFalse(result["rootPayloadVerified"])
            self.assertFalse(result["phoneModified"])
            for call in instance.obtain.call_args_list:
                self.assertEqual(call.kwargs["operation"],"analyze_function")
                self.assertEqual(call.kwargs["parameter"],"procedure")

    def test_execute_requires_installed_rea_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaisesRegex(m.OffsetREAError,"REA engine"):
                m.run_pipeline(root/"report",root/"image",root/"slices",root/"archive",
                               root/"src",root/"output",execute=True,
                               rea_script=root/"absent.mjs",node="node",timeout=300)
            self.assertFalse((root/"output").exists())

    def test_execution_refuses_outside_timeout_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);rea=root/"rea.mjs";rea.write_text("")
            with self.assertRaisesRegex(m.OffsetREAError,"timeout"):
                m.run_pipeline(root/"report",root/"image",root/"slices",root/"archive",
                               root/"src",root/"output",execute=True,
                               rea_script=rea,node="node",timeout=5)

    def test_cli_help_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                             cwd=tmp,capture_output=True,text=True,timeout=15)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn("--execute",p.stdout)
            self.assertIn("--stage3-report",p.stdout)

    def test_source_never_executes_firmware_or_writes_target(self):
        s=Path(m.__file__).read_text()
        for term in ("adb shell","fastboot flash","qemu-system-aarch64",
                     "target_h.write","git push","os.system("):
            self.assertNotIn(term,s)
        self.assertIn("Runner(",s)
        self.assertIn("analyze_function",s)
        self.assertIn("verify_rea_dossiers",s)

if __name__=="__main__":
    unittest.main()
