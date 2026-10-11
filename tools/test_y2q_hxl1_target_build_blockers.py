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

    def test_nonexistent_explicit_log_fails_instead_of_producing_empty_success(self):
        path=self.root/"does-not-exist"/"prior-build.log"
        with self.assertRaisesRegex(t.BlockerError,"Explicit --log does not exist"):
            t.logs_to_check(self.artifacts,[path])

    def test_explicit_symlink_is_rejected_before_previous_report_is_touched(self):
        original=self.save("kernel-build.log","kernel/futex.c:3: error: failed")
        linked=self.artifacts/"linked.log"
        linked.symlink_to(original)
        with self.assertRaisesRegex(t.BlockerError,"Explicit --log does not exist"):
            t.logs_to_check(self.artifacts,[linked])

    def test_two_runs_preserve_first_json_and_markdown_reports(self):
        desired=self.artifacts/"kernel-target-build-blockers.json"
        first=self.audit()
        old_json,old_md=t.write_new_report_pair(desired,first)
        old_content=old_json.read_text(),old_md.read_text()
        second=self.audit([self.save("samsung-hxl1-image-clang18-build-10.log",
             "arch/arm64/mm/cache.o: error: unrelated build stop")])
        newer_json,newer_md=t.write_new_report_pair(desired,second)
        self.assertNotEqual(old_json,newer_json)
        self.assertNotEqual(old_md,newer_md)
        self.assertEqual((old_json.read_text(),old_md.read_text()),old_content)
        self.assertIn("-run-001",str(newer_json))
        self.assertEqual(len(second["logEvidence"]),1)

    def test_assembler_failure_context_includes_neighboring_macro_expansion(self):
        log=self.save("samsung-hxl1-image-clang18-build-10.log",
            "clang -c arch/arm64/mm/cache.S\n"
            "<instantiation>:1:3: note: while in macro instantiation\n"
            "<instantiation>:2:2: error: unrecognized instruction mnemonic\n"
            "   2 | badinstruction\n"
            "      ^\n"
            "make[2]: *** [arch/arm64/mm/cache.o] Error 1\n")
        entry=t.scan_log(log)
        self.assertEqual(len(entry["assemblerMnemonicContexts"]),1)
        joined="\n".join(x["text"] for x in entry
                         ["assemblerMnemonicContexts"][0]["surroundingLines"])
        self.assertIn("badinstruction",joined)
        self.assertIn("cache.o",joined)

    def test_autodiscovery_excludes_ghidra_qemu_and_fix_review(self):
        actual=self.save("samsung-hxl1-image-clang18-build-10.log",
                         "arch/arm64/mm/cache.o: error: failure")
        self.save("hxl1-research/abl-linuxloader/rea-stage4-kernel-stderr.txt",
                  "fake error")
        self.save("qemu-lab/kernel-build.log","fake error")
        self.save("hxl1-research/rtmutex-fix-review/samsung-futex-excerpts.txt",
                  "fake error")
        self.assertEqual(t.logs_to_check(self.artifacts,[]),[actual])

    def test_new_reports_do_not_overwrite_broken_symlink_targets(self):
        desired=self.artifacts/"kernel-target-build-blockers.json"
        desired.symlink_to(self.artifacts/"does-not-exist.json")
        newer_json,newer_md=t.write_new_report_pair(desired,self.audit())
        self.assertTrue(desired.is_symlink())
        self.assertNotEqual(newer_json,desired)
        self.assertIn("-run-001",str(newer_json))

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


def re_marker_name(marker):
    return marker.replace(" ","_").replace(":","").replace("*","star")


# Additional per-target source attribution checks. These test distinctions
# actually needed with parallel Samsung make -j logs: same-line source
# diagnostics, errors on unrelated lines, and lookalike filenames.
ERROR_MARKERS=("fatal error:","error:","undefined reference","forbidden warning","***")
for target in ("rtmutex","futex"):
    for marker in ERROR_MARKERS:
        for representation in ("c","o"):
            for context in ("plain","clang","make"):
                def factory(name,diagnostic,suffix,style):
                    def test(self):
                        if style=="plain":
                            line=f"kernel/{name}.{suffix}: {diagnostic} cannot compile"
                        elif style=="clang":
                            line=f"/src/linux/kernel/{name}.{suffix}:99:3: {diagnostic} test"
                        else:
                            line=f"make[1]: *** [kernel/{name}.{suffix}] {diagnostic} test"
                        row=t.scan_log(self.save("kernel-build.log",line+"\n"))
                        self.assertEqual(len(row["targetErrorLines"]),1)
                        self.assertEqual(len(row["otherErrors"]),0)
                    return test
                setattr(EvidenceTests,
                        f"test_positive_{target}_{representation}_{context}_"+
                        re_marker_name(marker),
                        factory(target,marker,representation,context))

for target in ("rtmutex","futex"):
    for marker in ERROR_MARKERS:
        for context in ("source_first","error_first","verbose"):
            def factory(name,diagnostic,style):
                def test(self):
                    one=f"CC kernel/{name}.o"
                    two=f"arch/arm64/mm/cache.c:11: {diagnostic} unrelated"
                    if style=="error_first":
                        text=two+"\n"+one+"\n"
                    elif style=="verbose":
                        text=one+"\nINFO compiled many other objects\n"+two+"\n"
                    else:
                        text=one+"\n"+two+"\n"
                    item=t.scan_log(self.save("kernel-build.log",text))
                    self.assertEqual(item["targetMentions"],1)
                    self.assertEqual(item["targetErrorLines"],[])
                    self.assertGreaterEqual(len(item["otherErrors"]),1)
                return test
            setattr(EvidenceTests,
                    f"test_separate_lines_{target}_{context}_"+re_marker_name(marker),
                    factory(target,marker,context))

for target in ("rtmutex","futex"):
    for marker in ERROR_MARKERS:
        for mismatch in ("_extra.c","64.o","_copy.o"):
            def factory(name,diagnostic,suffix):
                def test(self):
                    row=t.scan_log(self.save(
                        "kernel-build.log",
                        f"kernel/{name}{suffix}: {diagnostic} unrelated target\n"
                    ))
                    self.assertEqual(row["targetErrorLines"],[])
                    self.assertEqual(row["targetMentions"],0)
                    self.assertEqual(len(row["otherErrors"]),1)
                return test
            setattr(EvidenceTests,
                    f"test_filename_lookalike_{target}_{re_marker_name(marker)}_"+
                    mismatch.strip("_").replace(".","_"),
                    factory(target,marker,mismatch))


if __name__=="__main__":
    unittest.main()
