"""Offline regression tests for HXL1 saved factory/REA static member-flow worklist."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from tools import y2q_hxl1_stage3_member_flow as m

def fake_records():
    data={name:{} for name in ("remove_waiter","rt_mutex_start_proxy_lock","futex_lock_pi")}
    for _,_,chain,_,_ in m.CHAINS:
        for pc,text in chain:data["remove_waiter"][pc]=text
    return data

def make_fixture(root):
    archive=root/"rea.zip"
    original={}
    with zipfile.ZipFile(archive,"w") as zipout:
        for name,rows in fake_records().items():
            key="abcdef"+name
            data={"operation":"read_function_instructions","provider":{"id":"ghidra"},
                  "subject":{"digest":{"sha256":key}},
                  "parameters":{"procedure":"0x10000"},
                  "normalized_result":{"instructions":[pc+": "+text for pc,text in rows.items()]}}
            zipout.writestr("rea-slice-"+name+"-"+key+".json",json.dumps(data))
            original[name]={
                "sourceElfSha256":key,"ghidraInstructionCount":len(rows),
                "actualGhidraRecordsIndependentlyChecked":True,
                "originalStockByteAttestation":{
                    "symbolVA":"0x"+key,"archivedGhidraInputMatchesOriginalFactoryImage":True
                }}
    src=root/"stage3.json"
    report={"schemaVersion":1,"firmware":"G986U1UESCHXL1",
            "stockOpcodeWitnessesVerified":31,"factoryMemberOffsetsVerified":0,
            "completeFactoryAbiVerified":False,"stage3Complete":False,
            "runtimeRootOrKernelSuProven":False,
            "memberCandidates":[{"type":t,"memberPath":n,
                                 "previousComparisonCandidateOffset":o}
                                for t,fields in m.prior.FIELDS.items() for n,o in fields.items()],
            "factoryInputIntegrity":{"kernel.bin":{
                "state":"VERIFIED","actualSha256":m.prior.ORIGINAL_IMAGE_SHA}},
            "reaEvidence":{"state":"31_ORIGINAL_OPCODE_WITNESSES_REA_ATTESTED",
                           "reaSha256":m.port.sha256(archive),
                           "savedGhidraDossiers":original}}
    src.write_text(json.dumps(report))
    return src,archive

class MemberFlowTests(unittest.TestCase):
    def test_new_comparisons_reject_wrong_base_or_access(self):
        sites={"lock":"0x100b8","prio":"0x100d0",
               "deadline":"0x101e0","task":"0x1013c"}
        for field,pc in sites.items():
            with self.subTest(member=field):
                records=fake_records()
                records["remove_waiter"][pc]="ldr x8, [sp, #0x38]"
                report=m.correlate(records,True)
                row=next(x for x in report["candidates"]
                         if x["type"]=="rt_mutex_waiter" and x["member"]==field)
                self.assertFalse(row["staticGhidraChainMatched"])
                self.assertFalse(row["factoryCMemberIdentityCertified"])

    def test_fixture_chains_cover_all_candidates_without_certification(self):
        r=m.correlate(fake_records(),True)
        self.assertEqual(r["matchedStaticChains"],13)
        self.assertEqual(len(r["candidates"]),13)
        self.assertEqual(r["factoryCertifiedMemberOffsets"],0)
        self.assertEqual(sum(not c["staticGhidraChainMatched"] for c in r["candidates"]),0)

    def test_missing_source_signature_never_credits_genuine_asm(self):
        r=m.correlate(fake_records(),False)
        self.assertEqual(r["matchedStaticChains"],0)

    def test_wrong_register_or_displacement_breaks_individual_chain(self):
        asm=fake_records()
        asm["remove_waiter"]["0x1003c"]="ldr x24, [x19, #0x18]"
        r=m.correlate(asm,True)
        self.assertLess(r["matchedStaticChains"],13)
        for c in r["candidates"]:
            if c["member"]=="owner":self.assertFalse(c["staticGhidraChainMatched"])

    def test_standalone_fixture_dossiers_bound_by_original_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report,archive=make_fixture(root)
            data=json.loads(report.read_text())
            asm=m.original_instructions(archive,data)
            self.assertEqual(asm["remove_waiter"]["0x1003c"],
                             "ldr x24, [x19, #0x20]")

    def test_archive_sha_mutation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report,archive=make_fixture(root)
            archive.write_bytes(archive.read_bytes()+b"oops")
            with self.assertRaisesRegex(m.FlowError,"digest"):
                m.original_instructions(archive,json.loads(report.read_text()))

    def test_missing_factory_byte_attestation_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report,archive=make_fixture(root)
            data=json.loads(report.read_text())
            data["reaEvidence"]["savedGhidraDossiers"]["remove_waiter"]["originalStockByteAttestation"]["archivedGhidraInputMatchesOriginalFactoryImage"]=False
            with self.assertRaisesRegex(m.FlowError,"authenticated"):
                m.original_instructions(archive,data)

    def test_saved_report_reconciliation_requires_all_thirteen(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report,archive=make_fixture(root)
            with patch.object(m,"source_signature",return_value=True):
                data=m.analyze(report,root,archive)
            self.assertEqual(data["registerFlowWorklist"]["matchedStaticChains"],13)
            self.assertEqual(data["factoryMemberOffsetsVerified"],0)
            self.assertFalse(data["stage3Complete"])
            self.assertFalse(data["rootOrKernelSuVerified"])

    def test_forged_report_claiming_stage3_complete_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report,archive=make_fixture(root)
            doc=json.loads(report.read_text())
            doc["stage3Complete"]=True
            report.write_text(json.dumps(doc))
            with self.assertRaisesRegex(m.FlowError,"report invalid"):
                m.analyze(report,root,archive)

    def test_wrong_member_map_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report,archive=make_fixture(root)
            doc=json.loads(report.read_text())
            doc["memberCandidates"][0]["previousComparisonCandidateOffset"]="0xdead"
            report.write_text(json.dumps(doc))
            with self.assertRaisesRegex(m.FlowError,"candidates mismatch"):
                m.analyze(report,root,archive)

    def test_no_recovery_payload_phone_or_guest_operations(self):
        source=Path(m.__file__).read_text()
        for forbidden in ("subprocess.run(", "adb shell", "fastboot flash",
                          "qemu-system-aarch64", "target_h.write", "git push"):
            self.assertNotIn(forbidden,source)

    def test_help_in_isolated_python(self):
        with tempfile.TemporaryDirectory() as temp:
            p=subprocess.run([sys.executable,"-I",str(Path(m.__file__)),"--help"],
                             cwd=temp,capture_output=True,text=True,timeout=15)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn("--verified-stage3-report",p.stdout)

if __name__=="__main__":
    unittest.main()
