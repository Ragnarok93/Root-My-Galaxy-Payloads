#!/usr/bin/env python3
"""Synthetic HXL1 missing-RT-mutex object/blocker evidence regression tests."""
from __future__ import annotations
import gzip
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import y2q_hxl1_target_build_blockers as t

def parent():
    return {
        "exactSourceAndBuildPinsVerified":True,
        "fullOriginalFactoryAbiEstablished":False,
        "rootDemonstrated":False,
        "selectedObjectDiagnostics":{
            name:{"classification":"OBJECT_MISSING",
                  "kbuildCommand":{"present":False}}
            for name in t.TARGETS
        },
    }

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.source=self.root/"stock"
        self.artifacts=self.root/"artifacts"
        (self.source/"kernel/locking").mkdir(parents=True)
        self.artifacts.mkdir()
        (self.source/"kernel/locking/Makefile").write_text(
            "obj-$(CONFIG_RT_MUTEXES) += rtmutex.o\n"
            "# obj-$(CONFIG_BAD) += rtmutex.o\n")
        (self.source/"kernel/Makefile").write_text(
            "obj-$(CONFIG_FUTEX) += futex.o\n"
            "obj-y += unrelated.o\n")
        (self.artifacts/"config.gz").write_bytes(gzip.compress(
            b"CONFIG_RT_MUTEXES=y\nCONFIG_FUTEX=y\n"
            b"# CONFIG_FUTEX_PI is not set\nCONFIG_DEBUG_INFO=y\n"
        ))
        self.previous=parent()

    def audit(self,logs=()):
        return t.reconcile(self.previous,self.source,self.artifacts,list(logs))

    def save(self,name,txt):
        file=self.artifacts/name
        file.parent.mkdir(exist_ok=True,parents=True)
        file.write_text(txt)
        return file

    def test_baseline_both_targets_are_missing_not_failed(self):
        x=self.audit()
        self.assertEqual(set(x["targetObjects"]),set(t.TARGETS))
        for info in x["targetObjects"].values():
            self.assertFalse(info["specificFailureCauseEstablished"])
            self.assertEqual(info["compilationActuallyAttempted"],"UNKNOWN")

    def test_original_rule_lookup_both_targets(self):
        x=self.audit()
        a=x["originalKbuildRules"]
        self.assertEqual(len(a["kernel/locking/Makefile"]["activeMatches"]),1)
        self.assertEqual(len(a["kernel/Makefile"]["activeMatches"]),1)

    def test_config_gates_read_as_verified_parent_data(self):
        x=self.audit()
        self.assertEqual(x["originalConfigFlags"]["CONFIG_RT_MUTEXES"],"y")
        self.assertEqual(x["originalConfigFlags"]["CONFIG_FUTEX"],"y")
        self.assertEqual(x["originalConfigFlags"]["CONFIG_FUTEX_PI"],"n")

    def test_missing_config_key_remains_not_listed(self):
        (self.artifacts/"config.gz").write_bytes(gzip.compress(b"CONFIG_RT_MUTEXES=y\n"))
        self.assertEqual(self.audit()["originalConfigFlags"]
                         ["CONFIG_FUTEX"],"NOT_LISTED")

    def test_no_historical_log_does_not_claim_compilation_failure(self):
        x=self.audit()
        self.assertEqual(x["logCandidatesChecked"],0)
        self.assertFalse(x["sourceRootOrRuntimeExploitValidated"])

    def test_explicit_same_line_target_error_is_evidence_only(self):
        p=self.save("build-10.log",
                    "kernel/locking/rtmutex.c:33:9: fatal error: missing.h\n"
                    "make: *** [kernel/locking/rtmutex.o] Error 1\n")
        x=self.audit([p])
        row=x["targetObjects"]["kernel/locking/rtmutex.o"]
        self.assertEqual(len(row["matchingHistoricalDiagnostic"]),2)
        self.assertFalse(row["specificFailureCauseEstablished"])

    def test_other_source_build_error_does_not_implicate_target(self):
        p=self.save("build-10.log","arch/arm64/mm/cache.c:99:7: error: bad thing\n")
        x=self.audit([p])
        self.assertEqual(x["targetObjects"]["kernel/futex.o"]
                         ["matchingHistoricalDiagnostic"],[])
        self.assertEqual(x["logEvidence"][0]["result"]["otherErrors"][0]
                         ["excerpt"].split(":")[0],"arch/arm64/mm/cache.c")

    def test_target_mention_without_error_does_not_mean_failure(self):
        p=self.save("build-10.log","CC kernel/futex.o\n")
        x=self.audit([p])
        self.assertEqual(x["logEvidence"][0]["result"]["targetMentions"],1)
        self.assertFalse(x["targetObjects"]["kernel/futex.o"]
                         ["matchingHistoricalDiagnostic"])

    def test_target_error_line_is_classified(self):
        p=self.save("kernel.log","kernel/futex.c:23: error: missing header\n")
        self.assertEqual(len(t.scan_log(p)["targetErrorLines"]),1)

    def test_clang_errors_from_elsewhere_separated(self):
        p=self.save("kernel.log","other/file.c:20: error: unexpected token\n")
        result=t.scan_log(p)
        self.assertEqual(len(result["targetErrorLines"]),0)
        self.assertEqual(len(result["otherErrors"]),1)

    def test_log_scan_does_not_promote_historic_error_to_root(self):
        p=self.save("kernel.log","kernel/futex.c:23: error: missing header\n")
        result=self.audit([p])
        self.assertFalse(result["productionKernelSUDeployable"])
        self.assertFalse(result["factoryStructureAbiProven"]) if (
            "factoryStructureAbiProven" in result) else self.assertFalse(
                result["stockCompilerAbiMatched"])

    def test_log_symlink_refused(self):
        p=self.save("kernel.log","kernel/futex.c:23: error: missing\n")
        link=self.artifacts/"linked.log"
        link.symlink_to(p)
        self.assertEqual(t.scan_log(link)["status"],"REFUSED_OR_MISSING")

    def test_oversized_log_bounded(self):
        p=self.save("build-10.log","example")
        with patch.object(t,"TAIL_BYTES",4):
            result=t.scan_log(p)
        self.assertEqual(result["status"],"PARTIAL_TAIL")
        self.assertFalse(result["complete"])

    def test_very_large_log_refused(self):
        p=self.save("build-10.log","stuff")
        with patch.object(t,"MAX_LOGS",1):
            self.assertEqual(t.logs_to_check(self.artifacts,[p,p]),[p])

    def test_duplicate_explicit_paths_deduplicated(self):
        p=self.save("build-10.log","x")
        self.assertEqual(t.logs_to_check(self.artifacts,[p,p]),[p])

    def test_log_autodiscovery_prefers_build_files(self):
        good=self.save("build-10.log","error")
        self.save("random.txt","no useful record")
        self.assertIn(good,t.logs_to_check(self.artifacts,[]))
        self.assertTrue(all("random" not in str(p) for p in
                            t.logs_to_check(self.artifacts,[])))

    def test_readonly_report_has_no_factory_offsets(self):
        text=t.markdown(self.audit())
        self.assertIn("do not",text.lower())
        self.assertIn("futex.o",text)
        self.assertIn("Clang18",text)
        self.assertIn("No compilation",text)

    def test_missing_makefile_is_unknown_not_an_error(self):
        (self.source/"kernel/Makefile").unlink()
        result=self.audit()
        self.assertEqual(result["originalKbuildRules"]["kernel/Makefile"]
                         ["status"],"UNAVAILABLE")

    def test_unverified_parent_rejected(self):
        self.previous["exactSourceAndBuildPinsVerified"]=False
        with self.assertRaisesRegex(t.BlockerError,"Untrusted"):
            self.audit()

    def test_claimed_factory_abi_rejected(self):
        self.previous["fullOriginalFactoryAbiEstablished"]=True
        with self.assertRaisesRegex(t.BlockerError,"Untrusted"):
            self.audit()

    def test_claimed_root_rejected(self):
        self.previous["rootDemonstrated"]=True
        with self.assertRaisesRegex(t.BlockerError,"Untrusted"):
            self.audit()

    def test_target_mysteriously_present_refused(self):
        self.previous["selectedObjectDiagnostics"][t.TARGETS[0]]["classification"]="EXPERIMENTAL_COMPLETE_DIE_FOUND"
        with self.assertRaisesRegex(t.BlockerError,"no longer reported missing"):
            self.audit()

    def test_absent_target_evidence_rejected(self):
        del self.previous["selectedObjectDiagnostics"][t.TARGETS[1]]
        with self.assertRaisesRegex(t.BlockerError,"Absent selected"):
            self.audit()

    def test_target_compile_command_kept_distinct(self):
        self.previous["selectedObjectDiagnostics"][t.TARGETS[0]]["kbuildCommand"]["present"]=True
        x=self.audit()
        self.assertTrue(x["targetObjects"][t.TARGETS[0]]["retainedCompileCommand"])
        self.assertFalse(x["targetObjects"][t.TARGETS[0]]
                         ["specificFailureCauseEstablished"])


# Every error marker and both target families are tested independently.
for kind,suffix in (
    ("fatal error:","fatal"),("error:","error"),
    ("undefined reference","undefined"),("forbidden warning","forbidden"),
    ("***","make_error"),
):
    for obj in ("rtmutex","futex"):
        def mk(marker,target):
            def test(self):
                row=f"kernel/locking/{target}.o: {marker} synthetic\n"
                x=t.scan_log(self.save("kernel-build.log",row))
                self.assertEqual(len(x["targetErrorLines"]),1)
                self.assertEqual(len(x["otherErrors"]),0)
            return test
        setattr(EvidenceTests,f"test_marker_{suffix}_{obj}",mk(kind,obj))


if __name__=="__main__":
    unittest.main()
