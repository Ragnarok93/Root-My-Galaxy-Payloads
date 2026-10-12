"""Automated, host-only nine-stage HXL1 gate orchestration tests."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_porting_automation as m

def sample_gates():
    return {
        "profile":"y2q-G986U1UESCHXL1",
        "payloadPortCompleted":False,
        "temporaryRootVerified":False,
        "kernelSuLoaded":False,
        "includedInProductionFeed":False,
        "gates":[{"stage":n,"title":m.STAGE_NAMES[n],
                  "state":"COMPLETE" if n<=2 else (
                      "PARTIAL" if n==3 else
                      "BLOCKED" if n in (7,8) else
                      "DEFERRED" if n==9 else "OPEN"),
                  "nextProof":"Factory or hardware proof still required"}
                 for n in range(1,10)]
    }

class Hxl1AutoPortTests(unittest.TestCase):
    def test_expected_tasks_span_actual_development_work_without_phone_actions(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/"new"
            rows=m.tasks(m.REPO,Path(temp),Path(temp)/"source",output,None)
            self.assertEqual([r.id for r in rows],[
                "01_readiness","03_layout","03_proof_matrix","03_clang10_checkpoint","03_export_table",
                "04_boot_v2","04_fdt_semantics","05_ghostlock_binary",
                "05_source_candidate","06_build_identity_only",
                "06_bundle_identity_only"])
            self.assertEqual([r.stage for r in rows],
                             [1,3,3,3,3,4,4,5,5,6,6])
            self.assertTrue(all(not any(b in r.script for b in (
                "adb","fastboot","qemu-system")) for r in rows))
            m.validate_plan(rows,output,m.REPO,Path(temp)/"source")

    def test_run_location_inside_git_repo_forbidden(self):
        out=m.REPO/"temporary-output-should-not-be-created"
        with self.assertRaisesRegex(m.PipelineError,"Refuse outputs inside"):
            m.validate_plan(m.tasks(m.REPO,m.ARTIFACTS,m.SOURCE,out,None),
                            out,m.REPO,m.SOURCE)

    def test_source_directory_output_forbidden(self):
        out=m.SOURCE/"source-not-for-running"
        with self.assertRaisesRegex(m.PipelineError,"Refuse outputs inside"):
            m.validate_plan(m.tasks(m.REPO,m.ARTIFACTS,m.SOURCE,out,None),
                            out,m.REPO,m.SOURCE)

    def test_existing_run_directory_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)
            with self.assertRaisesRegex(m.PipelineError,"must be new"):
                m.validate_plan(m.tasks(m.REPO,Path(tmp),m.SOURCE,out,None),
                                out,m.REPO,m.SOURCE)

    def test_exact_factory_hashes_pass_and_no_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"kernel.bin").write_bytes(b"unmodified-factory-fixture")
            (root/"config.gz").write_bytes(b"another-input")
            with patch.object(m,"PINNED_KERNEL",
                              hashlib.sha256(b"unmodified-factory-fixture").hexdigest()), \
                 patch.object(m,"PINNED_CONFIG",
                              hashlib.sha256(b"another-input").hexdigest()):
                got=m.check_factory_inputs(root)
            self.assertEqual({r["state"] for r in got.values()},{"VERIFIED"})

    def test_kernel_digest_mismatch_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"kernel.bin").write_bytes(b"wrong")
            (root/"config.gz").write_bytes(b"wrong")
            got=m.check_factory_inputs(root)
            self.assertEqual(got["kernel.bin"]["state"],"SHA256_MISMATCH")
            self.assertEqual(got["config.gz"]["state"],"SHA256_MISMATCH")

    def test_missing_kernel_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            got=m.check_factory_inputs(Path(tmp))
            self.assertEqual(got["kernel.bin"]["state"],"MISSING_OR_UNSAFE")

    def test_structural_stage_report_preserves_blockers(self):
        stage=m.validate_readiness(sample_gates())
        self.assertEqual(len(stage),9)
        self.assertEqual([g["state"] for g in stage].count("COMPLETE"),2)
        self.assertEqual(stage[2]["state"],"PARTIAL")
        self.assertEqual(stage[6]["state"],"BLOCKED")

    def test_missing_or_forged_production_gate_refused(self):
        r=sample_gates()
        r["includedInProductionFeed"]=True
        with self.assertRaisesRegex(m.PipelineError,"Unexpected deployability"):
            m.validate_readiness(r)

    def test_missing_stage_and_foreign_profile_refused(self):
        bad=sample_gates()
        bad["gates"]=bad["gates"][:-1]
        with self.assertRaisesRegex(m.PipelineError,"identity"):
            m.validate_readiness(bad)
        bad=sample_gates()
        bad["profile"]="sm-s921b"
        with self.assertRaisesRegex(m.PipelineError,"identity"):
            m.validate_readiness(bad)

    def test_dependency_failure_stops_unsafe_binary_build(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)
            s=m.Step("06_bundle_identity_only",6,"ignored",
                     ("bundle",),str(folder/"not-written"),
                     dependencies=("06_build_identity_only",))
            result=m.run_step(s,{"06_build_identity_only":"SKIP_MISSING_PREREQUISITE"},
                              folder,20,{})
            self.assertEqual(result["status"],"SKIP_DEPENDENCY")
            self.assertFalse((folder/"not-written").exists())

    def test_missing_optional_original_source_audit_is_skip(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            s=m.Step("05_source_candidate",5,"unused",(),
                     str(root/"not-written"),inputs=(str(root/"nope"),),
                     optional=True)
            result=m.run_step(s,{},root,20,{})
            self.assertEqual(result["status"],"SKIP_MISSING_PREREQUISITE")

    def test_missing_ndk_skips_diagnostic_not_fakes_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            script=root/"dummy.py"
            script.write_text("print('should not execute')\n")
            s=m.Step("06_build_identity_only",6,str(script),
                     ("build-probe","--scan-report",str(root/"scan"),
                      "--ndk",str(root/"absent"),"--output",str(root/"dummy.so")),
                     str(root/"dummy.so"),optional=True)
            r=m.run_step(s,{},root,20,{})
            self.assertEqual(r["status"],"SKIP_MISSING_PREREQUISITE")
            self.assertFalse((root/"dummy.so").exists())

    def test_existing_offline_python_step_executed_and_logged(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            helper=root/"helper.py"
            helper.write_text(
                "from pathlib import Path\nimport sys\n"
                "Path(sys.argv[1]).write_text('generated safely')\n"
                "print('fixture check passed')\n")
            dest=root/"fresh.txt"
            s=m.Step("synthetic",3,str(helper),(str(dest),),str(dest))
            r=m.run_step(s,{},root,20,{})
            self.assertEqual(r["status"],"PASS")
            self.assertEqual(r["sha256"],m.sha256(dest))
            self.assertIn("fixture check passed",
                          (root/"synthetic.log").read_text())
            self.assertFalse(r["rootOrKernelSuProven"])

    def test_failed_offline_step_keeps_diagnostic_log(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            helper=root/"bad.py"
            helper.write_text("raise SystemExit('no stock source')\n")
            r=m.run_step(m.Step("fake",3,str(helper),(),None),{},root,20,{})
            self.assertEqual(r["status"],"FAIL")
            self.assertIn("no stock source",(root/"fake.log").read_text())

    def test_stage6_filename_contract_matches_bundle_expectation(self):
        from tools import y2q_research_toolchain as bundle
        with tempfile.TemporaryDirectory() as temp:
            rows=m.tasks(m.REPO,Path(temp),Path(temp)/"source",
                         Path(temp)/"fresh",None)
            built=next(r for r in rows if r.id=="06_build_identity_only")
            packed=next(r for r in rows if r.id=="06_bundle_identity_only")
            self.assertEqual(Path(built.output).name,bundle.SHARED_LIBRARY)
            self.assertEqual(built.args[6],built.output)
            self.assertEqual(packed.args[4],built.output)
            self.assertIn("--manifest",built.args)
            self.assertIn("--manifest",packed.args)

    def test_markdown_renderer_emits_unescaped_backtick(self):
        report={"runId":"fixture","inputIntegrity":{},
                "steps":[{"id":"06_bundle_identity_only","stage":6,"status":"PASS"}],
                "stages":m.validate_readiness(sample_gates())}
        rendered=m.summarize(report)
        q=chr(96)
        self.assertIn(q+"fixture"+q,rendered)
        self.assertIn(q+"06_bundle_identity_only"+q,rendered)
        self.assertNotIn(chr(92)+q,rendered)

    def test_summary_never_confuses_task_pass_with_firmware_root(self):
        mfest={"runId":"fixture","inputIntegrity":{},
               "steps":[{"id":"03_layout","stage":3,"status":"PASS"}],
               "stages":m.validate_readiness(sample_gates())}
        text=m.summarize(mfest)
        self.assertIn("Stage 3",text)
        self.assertIn("factory",text)
        self.assertIn("cannot confer or prove root",text)
        self.assertNotIn("Root obtained",text)

    def test_plan_only_runs_with_no_factory_files_and_no_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"does-not-exist"
            c=subprocess.run([
                sys.executable,"-I",str(Path(m.__file__)),"--mode","plan",
                "--output-dir",str(path),"--artifacts",str(Path(tmp)/"none")],
                cwd=tmp,text=True,capture_output=True,timeout=20)
            self.assertEqual(c.returncode,0,c.stderr)
            self.assertIn("NO EXECUTION",c.stdout)
            self.assertFalse(path.exists())

    def test_disallow_readiness_without_vendor_kernel(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"not-generated"
            proc=subprocess.run([
                sys.executable,"-I",str(Path(m.__file__)),"--mode","run",
                "--artifacts",str(Path(tmp)/"missing"),
                "--output-dir",str(out)],
                cwd=tmp,text=True,capture_output=True,timeout=20)
            self.assertEqual(proc.returncode,2)
            self.assertIn("missing/mismatch",proc.stderr)
            self.assertFalse(out.exists())

    def test_single_command_wrapper_only_fast_forwards_and_runs_host_pipeline(self):
        wrapper=Path(m.REPO/"tools/run_y2q_hxl1_porting_automation.sh")
        body=wrapper.read_text()
        self.assertIn("git pull --ff-only",body)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1",body)
        self.assertIn("exec python3 tools/y2q_hxl1_porting_automation.py --mode run",body)
        for operation in ("git reset","git push","adb shell","fastboot","sudo ",
                          "qemu-system-aarch64","rm -rf"):
            self.assertNotIn(operation,body)
        proc=subprocess.run(["bash","-n",str(wrapper)],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0,proc.stderr)

    def test_static_refuse_phone_flash_feed_and_qemu_path(self):
        s=Path(m.__file__).read_text()
        for op in ("subprocess.Popen(","os.system(","requests.post(",
                   "fastboot flash","adb shell","qemu-system-aarch64"):
            self.assertNotIn(op,s)
        self.assertIn("validate_readiness",s)
        self.assertIn("check_factory_inputs",s)

if __name__=="__main__":
    unittest.main()
