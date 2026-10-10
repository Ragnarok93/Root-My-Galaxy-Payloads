#!/usr/bin/env python3
"""Synthetic original-loader function dossier validity tests."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_linuxloader_rea_stage4_functions as fn
from tools import y2q_linuxloader_rea_stage4_xrefs as xrefs


class FunctionDossierTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        loader=self.folder/"LinuxLoader-HXL1.efi"
        loader.write_bytes(b"synthetic fixture only")
        self.hash=fn.digest(loader)
        searches={}
        for label,group,textaddr,needle in fn.REFS:
            searches.setdefault(group,{"query":group,
                "status":"VERIFIED_STATIC_SEARCH",
                "evidenceId":"ev_seed_"+group,"hits":[]})
            searches[group]["hits"].append({"address":textaddr,"value":needle})
            source={"kernel-load-print":"0x2178c",
                    "kernel-dt-boundary":"0x216e8",
                    "best-dtb-match":"0x24e18"}[label]
            xref={
                "operation":"xrefs","provider":{"id":"ghidra"},
                "subject":{"digest":{"sha256":self.hash},"architecture":"arm64"},
                "parameters":{"address":textaddr},
                "evidence_id":"ev_ref_"+label,"normalized_result":[source],
            }
            self.write("rea-stage4-xrefs-"+label+".json",xref)
            body={"available":True,"provenance":"ghidra-function-body-address-set",
                  "ranges":[{"start":source,"end":source}]}
            dossier={
                "operation":"analyze_function","provider":{"id":"ghidra"},
                "subject":{"digest":{"sha256":self.hash},"architecture":"arm64"},
                "parameters":{"procedure":source},
                "evidence_id":"ev_function_"+label,
                "normalized_result":{
                    "procedure":{"name":"FUN_"+source,"address":source,"body":body},
                    "pseudocode":"void FUN() { }",
                    "native_value_flow":{"available":True}
                },
            }
            self.write("rea-stage4-function-"+label+".json",dossier)
        self.write("rea-stage4-seed-audit.json",
                   {"originalLoaderSha256":self.hash,
                    "queries":list(searches.values())})

    def write(self,name,content):
        (self.folder/name).write_text(json.dumps(content))

    def read(self,name):
        return json.loads((self.folder/name).read_text())

    def scan(self):
        with patch.object(fn,"LOADER_SHA256",self.hash):
            with patch.object(xrefs,"LOADER_SHA256",self.hash):
                return fn.analyze(self.folder)

    def test_three_original_xrefs_have_valid_containing_functions(self):
        res=self.scan()
        self.assertEqual(len(res["functions"]),3)
        self.assertTrue(all(x["status"]=="VERIFIED_FUNCTION" for x in res["functions"]))
        self.assertFalse(res["physicalKernelHandoffVerified"])

    def test_wrong_function_subject_digest_rejected(self):
        path="rea-stage4-function-kernel-load-print.json"
        record=self.read(path)
        record["subject"]["digest"]["sha256"]="0"*64
        self.write(path,record)
        result=self.scan()
        self.assertEqual(result["functions"][0]["status"],"FUNCTION_UNVERIFIED")

    def test_cross_reference_outside_claimed_body_rejected(self):
        path="rea-stage4-function-best-dtb-match.json"
        rec=self.read(path)
        rec["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x1000","end":"0x1100"}]
        self.write(path,rec)
        result=self.scan()
        self.assertEqual(result["functions"][2]["status"],"FUNCTION_UNVERIFIED")

    def test_foreign_function_query_rejected(self):
        path="rea-stage4-function-kernel-dt-boundary.json"
        rec=self.read(path)
        rec["parameters"]["procedure"]="0xdead"
        self.write(path,rec)
        result=self.scan()
        self.assertEqual(result["functions"][1]["status"],"FUNCTION_UNVERIFIED")

    def test_same_function_group_detected_only_when_range_corroborates(self):
        for label,source in (("kernel-load-print","0x2178c"),
                             ("kernel-dt-boundary","0x216e8")):
            name="rea-stage4-function-"+label+".json"
            rec=self.read(name)
            rec["normalized_result"]["procedure"]["address"]="0x21600"
            rec["normalized_result"]["procedure"]["body"]["ranges"]=[
                {"start":"0x21600","end":"0x217ff"}]
            self.write(name,rec)
        result=self.scan()
        self.assertEqual(result["sharedFunctions"],
                         [{"entry":"0x21600","labels":["kernel-load-print","kernel-dt-boundary"]}])

    def test_procedure_does_not_prove_physical_address(self):
        result=self.scan()
        self.assertFalse(result["physicalKernelHandoffVerified"])
        self.assertFalse(result["runtimeDtbSelectionVerified"])

    def test_malformed_source_address_fails_closed(self):
        path="rea-stage4-function-kernel-load-print.json"
        rec=self.read(path)
        rec["normalized_result"]["procedure"]["body"]["ranges"]=[
            {"start":"0x21600;bad","end":"0x217ff"}]
        self.write(path,rec)
        result=self.scan()
        self.assertEqual(result["functions"][0]["status"],"FUNCTION_UNVERIFIED")


if __name__=="__main__":
    unittest.main()
