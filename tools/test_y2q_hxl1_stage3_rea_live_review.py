"""Live REA/Ghidra Stage 3 original-byte verifier and safe command regression."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import y2q_hxl1_stage3_rea_live_review as m
from tools import test_y2q_hxl1_stage3_member_flow as fixtures

def fake_native(sha="ab"*32):
    return {"operation":"read_function_instructions",
            "provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":sha},"architecture":"arm64"},
            "parameters":{"procedure":"0x10000"},
            "evidence_id":"ev_fake_native",
            "normalized_result":{"instructions":[
                "0x10000: ldr x8, [x0, #0x10]",
                "0x10004: ret"]}}

class LiveStage3ReaTests(unittest.TestCase):
    def test_coverage_separates_absent_comparison_from_mismatch(self):
        report={"functions":{"large":{
            "freshGhidraInstructions":{"nativeIdenticalToFactoryBoundArchive":True},
            "freshGhidraFunction":{"highPcodeCompleteWithinProviderLimits":False,
                                    "highPcodeTruncated":True}}},
            "memberCandidateRegisterFlow":{"candidates":[
                {"type":"sample","member":"absent","staticGhidraChainMatched":False},
                {"type":"sample","member":"different","steps":[{}],"staticGhidraChainMatched":False},
                {"type":"sample","member":"same","steps":[{}],"staticGhidraChainMatched":True}]}}
        before=json.dumps(report)
        result=m.analysis_coverage(report)
        self.assertEqual(result["functions"][0]["highPcodeStatus"],"TRUNCATED")
        self.assertEqual([x["status"] for x in result["memberComparisons"]],
                         ["UNIMPLEMENTED_COMPARISON","MISMATCH","MATCHED_STATIC_CHAIN"])
        self.assertFalse(result["factoryMemberIdentityPromoted"])
        self.assertEqual(json.dumps(report),before)

    def make_attestation_fixture(self):
        old={}
        verified={}
        for name in m.TARGETS:
            base={"ghidraInstructionCount":4,
                  "sourceElfSha256":"ab"*32,
                  "actualGhidraRecordsIndependentlyChecked":True,
                  "sourceToCMemberFullDefUseCertified":False}
            old[name]=dict(base)
            verified[name]={**base, "originalStockByteAttestation":{
                "symbolVA":"0xffffff8008147db4",
                "archivedGhidraInputMatchesOriginalFactoryImage":True}}
        return old,verified

    def test_legacy_report_gains_authenticated_bytes_in_memory_only(self):
        old,verified=self.make_attestation_fixture()
        report={"reaEvidence":{"savedGhidraDossiers":old}}
        before=json.dumps(report,sort_keys=True)
        upgraded=m.reconcile_original_dossiers(report,verified)
        self.assertTrue(upgraded["legacyStage3ReportRevalidatedInMemory"])
        self.assertEqual(upgraded["reaEvidence"]["savedGhidraDossiers"],verified)
        self.assertEqual(json.dumps(report,sort_keys=True),before)
        self.assertNotIn("originalStockByteAttestation",
                         report["reaEvidence"]["savedGhidraDossiers"]["remove_waiter"])

    def test_current_report_with_good_attestation_is_also_accepted(self):
        _,verified=self.make_attestation_fixture()
        original={"reaEvidence":{"savedGhidraDossiers":verified}}
        upgraded=m.reconcile_original_dossiers(original,verified)
        self.assertFalse(upgraded["legacyStage3ReportRevalidatedInMemory"])

    def test_old_report_cannot_override_mismatched_elf_sha(self):
        old,verified=self.make_attestation_fixture()
        old["remove_waiter"]["sourceElfSha256"]="00"*32
        with self.assertRaisesRegex(m.LiveProofError,"sourceElfSha256"):
            m.reconcile_original_dossiers({"reaEvidence":{"savedGhidraDossiers":old}},verified)

    def test_current_report_cannot_override_false_byte_attestation(self):
        _,verified=self.make_attestation_fixture()
        old=json.loads(json.dumps(verified))
        old["futex_lock_pi"]["originalStockByteAttestation"][
            "archivedGhidraInputMatchesOriginalFactoryImage"]=False
        with self.assertRaisesRegex(m.LiveProofError,"attestation changed"):
            m.reconcile_original_dossiers({"reaEvidence":{"savedGhidraDossiers":old}},verified)

    def test_duplicate_or_missing_ghidra_dossiers_rejected(self):
        old,verified=self.make_attestation_fixture()
        old.pop("futex_lock_pi")
        with self.assertRaisesRegex(m.LiveProofError,"inventory"):
            m.reconcile_original_dossiers({"reaEvidence":{"savedGhidraDossiers":old}},verified)

    def test_incomplete_new_factory_attestation_cannot_be_promoted(self):
        old,verified=self.make_attestation_fixture()
        verified["remove_waiter"]["originalStockByteAttestation"]=None
        with self.assertRaisesRegex(m.LiveProofError,"incomplete"):
            m.reconcile_original_dossiers({"reaEvidence":{"savedGhidraDossiers":old}},verified)

    def test_saved_report_legacy_6bb5f68_schema_is_revalidated_and_preserved(self):
        from tools import y2q_hxl1_porting_automation as port
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            image=root/"kernel.bin"
            image.write_bytes(b"original-stock-fixture")
            slices=root/"slices.zip"
            archive=root/"rea.zip"
            slices.write_bytes(b"slice-fixture")
            archive.write_bytes(b"rea-fixture")
            old,verified=self.make_attestation_fixture()
            integrity={"kernel.bin":{"state":"VERIFIED"},
                       "config.gz":{"state":"VERIFIED"}}
            original={"schemaVersion":1,"firmware":"G986U1UESCHXL1",
                      "stockOpcodeWitnessesVerified":31,
                      "factoryMemberOffsetsVerified":0,"stage3Complete":False,
                      "factoryInputIntegrity":integrity,
                      "memberCandidates":[{"type":ty,"memberPath":field,
                           "previousComparisonCandidateOffset":offset}
                          for ty,table in m.prior.FIELDS.items()
                          for field,offset in table.items()],
                      "reaEvidence":{"slicesSha256":port.sha256(slices),
                                     "reaSha256":port.sha256(archive),
                                     "state":"31_ORIGINAL_OPCODE_WITNESSES_REA_ATTESTED",
                                     "savedGhidraDossiers":old}}
            prior=root/"owner-20261012-stage3.json"
            raw=json.dumps(original)
            prior.write_text(raw)
            with patch.object(port,"check_factory_inputs",return_value=integrity), \
                 patch.object(m.prior,"source_headers",return_value={}), \
                 patch.object(m.offset,"verify_rea_dossiers",return_value=verified) as called:
                upgraded,dossiers=m.saved_report(prior,root,root/"source",archive,slices)
            called.assert_called_once()
            self.assertEqual(dossiers,verified)
            self.assertTrue(upgraded["legacyStage3ReportRevalidatedInMemory"])
            self.assertEqual(upgraded["reaEvidence"]["savedGhidraDossiers"],verified)
            self.assertEqual(prior.read_text(),raw)

    def test_only_three_original_ghidra_functions(self):
        self.assertEqual(m.TARGETS,("remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi"))

    def test_typed_13_member_registry_preserved(self):
        self.assertEqual(sum(map(len,m.prior.FIELDS.values())),13)

    def test_live_ghidra_site_index_has_13_candidates_without_fabricating_members(self):
        inventory=m.ghidra_member_displacement_leads({
            "remove_waiter":{"0x10018":"ldr x22, [x0, #0x18]",
                             "0x1003c":"ldr x24, [x19, #0x20]",
                             "0x100b0":"ldr x0, [x19, #0x0]"},
            "futex_lock_pi":{"0x100a0":"ldr w2, [x21, #0x40]"}
        })
        self.assertEqual(len(inventory),13)
        self.assertFalse(any(x["CFieldIdentityCertified"] for x in inventory))
        self.assertTrue(next(x for x in inventory
                             if x["type"]=="rt_mutex" and x["member"]=="owner")
                        ["exactFactoryGhidraMemoryOperandCandidates"])
        self.assertTrue(next(x for x in inventory
                             if x["type"]=="rt_mutex_waiter" and x["member"]=="prio")
                        ["exactFactoryGhidraMemoryOperandCandidates"])

    def test_stack_immediates_are_not_accepted_as_member_displacements(self):
        items=m.ghidra_member_displacement_leads({
            "remove_waiter":{"0x10010":"stp x22, x21, [sp, #0x20]",
                             "0x10028":"ldr x8, [x22, #0x38]",
                             "0x100d0":"ldr w10, [x0, #0x40]"}
        })
        owner=next(v for v in items if v["type"]=="rt_mutex" and v["member"]=="owner")
        self.assertEqual(owner["stackFrameFalsePositiveCount"],1)
        self.assertEqual(owner["nonstackOperandLeadCount"],0)
        self.assertEqual(owner["exactFactoryGhidraMemoryOperandCandidates"][0][
            "evidenceClass"],"STACK_FRAME_NOT_C_MEMBER")
        waiter=next(v for v in items if v["type"]=="rt_mutex_waiter" and v["member"]=="lock")
        self.assertEqual(waiter["nonstackOperandLeadCount"],1)
        self.assertEqual(waiter["stackFrameFalsePositiveCount"],0)
        self.assertFalse(waiter["CFieldIdentityCertified"])
        priority=next(v for v in items if v["type"]=="rt_mutex_waiter" and v["member"]=="prio")
        self.assertEqual(priority["nonstackOperandLeadCount"],1)
        self.assertFalse(priority["CFieldIdentityCertified"])

    def test_ghidra_pcode_incomplete_when_omitted_edges_remain(self):
        ev={"operation":"analyze_function","provider":{"id":"ghidra"},
            "subject":{"digest":{"sha256":"ab"*32}},
            "parameters":{"procedure":"0x10000"},
            "evidence_id":"ev_pcode",
            "normalized_result":{
                "procedure":{"address":"0x10000","name":"remove_waiter",
                             "body":{"available":True,"ranges":[
                                 {"start":"0x10000","end":"0x10120"}]}},
                "pseudocode":"void remove_waiter() { return; }",
                "native_value_flow":{"available":True,
                    "truncated":False,"omitted_operations_lower_bound":0,
                    "known_omitted_inputs":0,"known_omitted_edges":0,
                    "operations":[{"opcode":"LOAD"}]}}}
        complete=m.review_genuine_ghidra("remove_waiter","0x10000",ev,"ab"*32)
        self.assertTrue(complete["highPcodeCompleteWithinProviderLimits"])
        self.assertEqual(complete["retainedHighPcodeOperations"],1)
        ev["normalized_result"]["native_value_flow"]["truncated"]=True
        ev["normalized_result"]["native_value_flow"]["known_omitted_edges"]=52
        partial=m.review_genuine_ghidra("remove_waiter","0x10000",ev,"ab"*32)
        self.assertFalse(partial["highPcodeCompleteWithinProviderLimits"])
        self.assertTrue(partial["highPcodeTruncated"])
        self.assertEqual(partial["knownOmittedPcodeEdges"],52)

    def test_native_requires_exact_original_elf_hash(self):
        with self.assertRaisesRegex(m.LiveProofError,"provenance"):
            m.native_map(fake_native(), "cd"*32)
        d=m.native_map(fake_native(),"ab"*32)
        self.assertEqual(d["0x10000"],"ldr x8, [x0, #0x10]")

    def test_native_mismatch_cannot_validate_original_field(self):
        saved={"0x10000":"ldr x8, [x0, #0x18]",
               "0x10004":"ret"}
        result=m.compare_live_native(m.native_map(fake_native(),"ab"*32),saved)
        self.assertFalse(result["nativeIdenticalToFactoryBoundArchive"])
        self.assertEqual(result["differentOrMissingInstructionCount"],1)

    def test_native_duplicate_pc_fails_closed(self):
        e=fake_native()
        e["normalized_result"]["instructions"].append("0x10000: nop")
        with self.assertRaisesRegex(m.LiveProofError,"duplicate"):
            m.native_map(e,"ab"*32)

    def test_no_injection_via_string_object_in_native(self):
        e=fake_native()
        e["normalized_result"]["instructions"]=[{"addr":"0x10000","opcode":"mov"}]
        with self.assertRaisesRegex(m.LiveProofError,"invalid live"):
            m.native_map(e,"ab"*32)

    def test_function_original_elf_hash_required(self):
        e={"operation":"analyze_function","provider":{"id":"ghidra"},
           "subject":{"digest":{"sha256":"ab"*32}},
           "parameters":{"procedure":"0x10000"}}
        with self.assertRaisesRegex(m.LiveProofError,"exact isolated ELF"):
            m.review_genuine_ghidra("remove_waiter","0x10000",e,"cd"*32)

    def test_function_attested_body_and_not_just_pseudocode(self):
        e={"operation":"analyze_function","provider":{"id":"ghidra"},
           "subject":{"digest":{"sha256":"ab"*32}},
           "parameters":{"procedure":"0x10000"},
           "evidence_id":"ev_func",
           "normalized_result":{
               "procedure":{"address":"0x10000","name":"FUN_00010000",
                 "body":{"available":True,"ranges":[
                      {"start":"0x10000","end":"0x10120"}]}},
               "pseudocode":"void FUN_00010000() { /* rt_mutex.owner hypothesis */ }",
               "native_value_flow":{"available":True}
           }}
        info=m.review_genuine_ghidra("remove_waiter","0x10000",e,"ab"*32)
        self.assertTrue(info["pcodeAvailable"])
        self.assertIn("owner",info["lexicalMemberNameHints"])
        self.assertFalse(info["sourceAndRegisterToCFieldIdentityProven"])
        self.assertEqual(info["factoryMemberOffsetsCertified"],0)

    def test_plan_does_not_call_ghidra_or_make_output(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            dest=base/"future"
            sha="ab"*32
            report={"reaEvidence":{"savedGhidraDossiers":{}}}
            (base/"saved").write_text("{}")
            inp={name:{"archiveMember":name+".elf",
                       "sha256":sha,"factoryStaticVA":"0x1",
                       "fileBytes":b"fixture"} for name in m.TARGETS}
            with patch.object(m,"saved_report",return_value=(report,{})), \
                 patch.object(m,"slice_manifest",return_value=inp), \
                 patch.object(m.flow,"original_instructions",return_value={name:{} for name in m.TARGETS}), \
                 patch.object(m,"Runner") as runner:
                res=m.run(base/"saved",base,base/"src",base/"slices.zip",
                          base/"rea.zip",base/"missing.mjs",dest,False,240)
                runner.assert_not_called()
            self.assertEqual(res["mode"],"PLAN_ONLY")
            self.assertEqual(len(res["planned"]),3)
            self.assertFalse(dest.exists())

    def test_execute_exact_six_read_only_ghidra_queries(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            dest=base/"fresh"
            import hashlib
            sha=hashlib.sha256(b"fixture").hexdigest()
            report={"reaEvidence":{"savedGhidraDossiers":{}}}
            (base/"saved").write_text("{}")
            (base/"slices.zip").write_bytes(b"fixture slices")
            (base/"rea.zip").write_bytes(b"fixture rea")
            subjects={name:{"archiveMember":name+".elf",
                            "sha256":sha,"factoryStaticVA":"0x1",
                            "fileBytes":b"fixture"}
                      for name in m.TARGETS}
            saved_map=m.native_map(fake_native(sha),sha)
            class FakeRunner:
                queries=[]
                def __init__(self,*args,**kwargs):
                    self.kwargs=kwargs
                def obtain(self,target,args,dest,**kwargs):
                    self.queries.append((target.name,args[0],kwargs["operation"]))
                    if kwargs["operation"]=="read_function_instructions":
                        return fake_native(sha)
                    return {"operation":"analyze_function","provider":{"id":"ghidra"},
                            "subject":{"digest":{"sha256":sha}},
                            "parameters":{"procedure":"0x10000"},
                            "evidence_id":"ev_mock"}
            script=base/"rea.mjs"
            script.write_text("fixture")
            with patch.object(m,"saved_report",return_value=(report,{})), \
                 patch.object(m,"slice_manifest",return_value=subjects), \
                 patch.object(m.flow,"original_instructions",return_value={
                     name:saved_map for name in m.TARGETS}), \
                 patch.object(m.flow,"source_signature",return_value=True), \
                 patch.object(m,"Runner",FakeRunner), \
                 patch.object(m,"review_genuine_ghidra",return_value={
                     "factoryMemberOffsetsCertified":0,
                     "highPcodeCompleteWithinProviderLimits":False}):
                result=m.run(base/"saved",base,base/"src",base/"slices.zip",
                             base/"rea.zip",script,dest,True,240)
            self.assertEqual(len(FakeRunner.queries),6)
            self.assertEqual({q[1] for q in FakeRunner.queries},{"instructions","function"})
            self.assertEqual(result["factoryMemberOffsetsVerified"],0)
            self.assertEqual(result["memberCandidateRegisterFlow"]["factoryCertifiedMemberOffsets"],0)
            self.assertFalse(result["stage3Complete"])
            self.assertTrue((dest/"live-stage3-rea-review.json").is_file())

    def test_existing_output_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with patch.object(m,"saved_report",return_value=({"reaEvidence":{}},{})):
                with self.assertRaisesRegex(m.LiveProofError,"output directory exists"):
                    m.run(root/"saved",root,root/"src",root/"slices.zip",
                          root/"rea.zip",root/"rea.mjs",root,False,240)

    def test_source_safety_and_no_exploit_or_device_calls(self):
        code=Path(m.__file__).read_text()
        for text in ("adb shell","fastboot flash","qemu-system-aarch64",
                     "target_h.write","git push","write_kernel"):
            self.assertNotIn(text,code)
        self.assertIn("Runner(",code)
        self.assertIn('["function",str(binary),"0x10000"]',code)
        self.assertIn('["instructions",str(binary),"0x10000"]',code)

    def test_isolated_python_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            run=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                               cwd=temp,text=True,capture_output=True,timeout=20)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn("--execute",run.stdout)
            self.assertIn("--verified-stage3-report",run.stdout)

if __name__=="__main__":
    unittest.main()
