#!/usr/bin/env python3
"""Independent Stage 3/HXL1 parent-schema and evidence promotion regressions.

Tests exercise strict compatibility across five actual in-repo audit schemas,
with separate cases for each previously unproven factory ABI/runtime gate.
"""
from __future__ import annotations
import copy
import unittest
from tools import y2q_hxl1_kernel_proof_matrix as mod


def reports():
    inventory={
        "model":mod.TARGET,"firmware":mod.FIRMWARE,"stockKernel":mod.RELEASE,
        "originalFileHashChecksPassed":True,
        "offsetsVerified":False,"sourceToLiveDeviceLayoutVerified":False,
        "root":False,
        "sourceDeclarations":{
            name:{"definitions":[{"path":"a.h","line":1}],
                  "verifiedOffsets":False,"configuredLayoutVerified":False}
            for name in mod.EXPECTED_STRUCTS
        },
        "sourceConfig":{"CONFIG_DEBUG_INFO":"n"},
        "analysisElf":{"state":"NO_DEBUG_INFO","debug":[],"btf":False},
    }
    partial={
        "target":f"{mod.TARGET} {mod.FIRMWARE}",
        "originalHashPinsMatched":True,
        "buildConfigSha256":mod.build.GENERATED_SHA,
        "factoryAbiVerified":False,"numericOffsetsVerified":False,
        "actualRootPayloadAvailable":False,"phoneTouched":False,
        "configParity":{"compilerVersionMatches":False,
                        "commonDifferences":{"CONFIG_CLANG_VERSION":{"generated":"18","stock":"10"}}},
        "selected":{"kernel/futex.o":{"kind":"ARM64_REL","hasDwarf":True}},
        "objectCount":77,"arm64RelCount":77,"arm64DwarfCount":61,
    }
    presence={
        "target":f"Samsung {mod.TARGET} {mod.FIRMWARE}",
        "verifiedConfigSha256":mod.build.GENERATED_SHA,
        "zeroExitDoesNotProveTypePresence":True,
        "stockFirmwareLayoutVerified":False,
        "runtimeKernelCodeExecuted":False,"rootVerified":False,
        "aarch64ObjectsInspected":77,
        "types":{
            name:{"objectsChecked":77,"completeDefinitionsFound":0,
                  "presentIn":[],"ambiguousOrToolError":[]}
            for name in mod.REQUIRED_TYPES
        },
    }
    fix={
        "firmware":f"{mod.TARGET} / {mod.FIRMWARE}",
        "stockKernel":mod.RELEASE,"samsungSourceHashesVerified":True,
        "ownershipMismatchSourcePattern":True,
        "publishedFixDiffsComplete":True,"runtimeCveReproduced":False,
        "onPhoneRootVerified":False,"kernelSuValidated":False,
        "deviceModified":False,
    }
    stages=["COMPLETE","COMPLETE","PARTIAL","OPEN","OPEN","OPEN",
            "BLOCKED","BLOCKED","DEFERRED"]
    port={
        "profile":f"y2q-{mod.FIRMWARE}","firmware":mod.FIRMWARE,
        "kernel":mod.RELEASE,"payloadPortCompleted":False,
        "ghostLockRuntimeValidated":False,"temporaryRootVerified":False,
        "kernelSuLoaded":False,"phoneChanged":False,
        "includedInProductionFeed":False,
        "rawBtfSearch":{"status":"NO_RAW_BTF_CANDIDATE","candidates":[]},
        "gates":[{"stage":i+1,"title":"stage "+str(i+1),"state":v}
                 for i,v in enumerate(stages)],
    }
    return (inventory,partial,presence,fix,port)


class StageThreeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.report=list(reports())

    def run_audit(self):
        return mod.build_matrix(*self.report)

    def test_all_readonly_sources_are_kept_distinct(self):
        x=self.run_audit()
        self.assertTrue(x["checks"]["stockHashesAndSourcePinned"])
        self.assertEqual(len(x["checks"]["sourceDeclarations"]),7)
        self.assertEqual(len(x["checks"]["rtMutexTypePresence"]),2)
        self.assertEqual(len(x["checks"]["readinessStages"]),9)
        self.assertEqual(x["decisions"]["stage3"],"PARTIAL")

    def test_no_runtime_or_kernel_su_promotion(self):
        d=self.run_audit()["decisions"]
        for flag in (
            "originalCompiledStructureOffsetsVerified",
            "compilerAbiEquivalentToFactoryProven",
            "originalRuntimeKernelPhysicalBaseMeasured",
            "perBootKernelSlideKnown",
            "samsungSecurityCompatibilityValidated",
            "ghostLockRuntimeApplicable",
            "kernelSuCompatibleAndAuthorized",
            "productionSupportFeedPermitted",
            "deviceModified",
        ):
            self.assertIs(d[flag],False,flag)

    def test_pahole_type_present_is_not_factory_abi(self):
        self.report[2]["types"]["rt_mutex_waiter"]["completeDefinitionsFound"]=1
        self.report[2]["types"]["rt_mutex_waiter"]["presentIn"]=["kernel/futex.o"]
        d=self.run_audit()
        self.assertEqual(d["checks"]["rtMutexTypePresence"]["rt_mutex_waiter"]
                         ["completeDefinitionsFound"],1)
        self.assertFalse(d["decisions"]["originalCompiledStructureOffsetsVerified"])

    def test_clang_version_match_is_not_oem_layout(self):
        self.report[1]["configParity"]["compilerVersionMatches"]=True
        d=self.run_audit()
        self.assertTrue(d["checks"]["partialCompilerBuild"]
                        ["generatedVsStockCompilerVersionEqual"])
        self.assertFalse(d["decisions"]["compilerAbiEquivalentToFactoryProven"])

    def test_source_headers_are_not_compiled_offsets(self):
        self.report[0]["sourceDeclarations"]["rt_mutex_waiter"]["definitions"]=[]
        x=self.run_audit()
        self.assertFalse(x["checks"]["sourceDeclarations"]["rt_mutex_waiter"]
                         ["declarationPresent"])
        self.assertFalse(x["decisions"]["originalCompiledStructureOffsetsVerified"])

    def test_markdown_exposes_all_proof_gaps(self):
        md=mod.markdown(self.run_audit())
        self.assertIn("rt_mutex_waiter",md)
        self.assertIn("Clang18",md)
        self.assertIn("runtime physical kernel load",md)
        self.assertIn("Root",md) if "Root" in md else self.assertIn("root",md)
        self.assertIn("Deployment permitted:** NO",md)

    def test_multiple_partial_objects_do_not_bypass_factory_checks(self):
        self.report[1]["objectCount"]=100000
        self.report[1]["arm64DwarfCount"]=100000
        x=self.run_audit()
        self.assertFalse(x["checks"]["partialCompilerBuild"]["factoryAbiAuthenticated"])

    def test_zero_pahole_exit_does_not_prove_presence(self):
        self.report[2]["types"]["rt_mutex"]["completeDefinitionsFound"]=0
        self.report[2]["types"]["rt_mutex"]["presentIn"]=[]
        x=self.run_audit()
        self.assertEqual(x["checks"]["rtMutexTypePresence"]["rt_mutex"]
                         ["completeDefinitionsFound"],0)

    def test_compiler_mismatch_reported_not_hidden(self):
        x=self.run_audit()
        self.assertEqual(
            x["checks"]["partialCompilerBuild"]["changedEffectiveConfigItems"]
              ["CONFIG_CLANG_VERSION"]["generated"],"18")

    def test_source_bug_signal_not_runtime_exploit(self):
        x=self.run_audit()
        self.assertTrue(x["checks"]["rtMutexSourceVsFix"]
                        ["sourcePatternMatchesPublishedBugReview"])
        self.assertFalse(x["checks"]["rtMutexSourceVsFix"]
                         ["onDeviceCveApplicabilityProven"])

    def test_seven_source_declarations_are_expected(self):
        self.assertEqual(len(mod.EXPECTED_STRUCTS),7)

    def test_factory_evidence_not_derived_from_recovered_elf(self):
        x=self.run_audit()
        self.assertFalse(x["decisions"]["originalRuntimeKernelPhysicalBaseMeasured"])
        self.assertFalse(x["decisions"]["perBootKernelSlideKnown"])

    def test_partial_build_with_no_objects_is_not_successful_layout(self):
        self.report[1]["objectCount"]=0
        self.report[1]["arm64RelCount"]=0
        self.report[1]["arm64DwarfCount"]=0
        x=self.run_audit()
        self.assertFalse(x["decisions"]["originalCompiledStructureOffsetsVerified"])


def must_fail(name,edit,expected):
    def test(self):
        edit(self.report)
        with self.assertRaisesRegex(mod.ProofError,expected):
            self.run_audit()
    test.__name__="test_reject_"+name
    return test


MODIFICATIONS=[
    ("wrong_model",lambda q:q[0].__setitem__("model","SM-G981U"),"identity"),
    ("wrong_fw",lambda q:q[0].__setitem__("firmware","OLDER"),"identity"),
    ("wrong_kernel",lambda q:q[0].__setitem__("stockKernel","5.4"),"identity"),
    ("missing_kernel_hash",lambda q:q[0].__setitem__("originalFileHashChecksPassed",None),"SHA256"),
    ("wrong_oem_offsets",lambda q:q[0].__setitem__("offsetsVerified",True),"layouts"),
    ("wrong_live_layout",lambda q:q[0].__setitem__("sourceToLiveDeviceLayoutVerified",True),"layouts"),
    ("source_root_claim",lambda q:q[0].__setitem__("root",True),"layouts"),
    ("missing_struct",lambda q:q[0]["sourceDeclarations"].pop("rt_mutex"),"declaration labels"),
    ("added_unknown_struct",lambda q:q[0]["sourceDeclarations"].__setitem__("external",{}),"declaration labels"),
    ("declaration_false_layout",lambda q:q[0]["sourceDeclarations"]["rt_mutex_waiter"].__setitem__("verifiedOffsets",True),"compiled offsets"),
    ("declaration_false_config",lambda q:q[0]["sourceDeclarations"]["rt_mutex"].__setitem__("configuredLayoutVerified",True),"compiled offsets"),
    ("clang18_wrong_config",lambda q:q[1].__setitem__("buildConfigSha256","b"*64),"provenance"),
    ("clang18_wrong_target",lambda q:q[1].__setitem__("target","OTHER"),"provenance"),
    ("clang18_false_factory",lambda q:q[1].__setitem__("factoryAbiVerified",True),"promoted"),
    ("clang18_false_offsets",lambda q:q[1].__setitem__("numericOffsetsVerified",True),"promoted"),
    ("clang18_false_root",lambda q:q[1].__setitem__("actualRootPayloadAvailable",True),"promoted"),
    ("clang18_false_phone",lambda q:q[1].__setitem__("phoneTouched",True),"promoted"),
    ("clang18_missing_parity",lambda q:q[1].pop("configParity"),"comparison malformed"),
    ("clang18_neg_objects",lambda q:q[1].__setitem__("objectCount",-1),"comparison malformed"),
    ("pahole_wrong_target",lambda q:q[2].__setitem__("target","OTHER"),"probe"),
    ("pahole_wrong_hash",lambda q:q[2].__setitem__("verifiedConfigSha256","b"*64),"probe"),
    ("pahole_bad_zero_exit",lambda q:q[2].__setitem__("zeroExitDoesNotProveTypePresence",False),"probe"),
    ("pahole_false_factory",lambda q:q[2].__setitem__("stockFirmwareLayoutVerified",True),"factory offsets"),
    ("pahole_false_runtime",lambda q:q[2].__setitem__("runtimeKernelCodeExecuted",True),"factory offsets"),
    ("pahole_false_root",lambda q:q[2].__setitem__("rootVerified",True),"factory offsets"),
    ("pahole_missing_type",lambda q:q[2]["types"].pop("rt_mutex"),"type presence"),
    ("pahole_extra_type",lambda q:q[2]["types"].__setitem__("task_struct",{}),"type presence"),
    ("pahole_wrong_count",lambda q:q[2]["types"]["rt_mutex"].__setitem__("objectsChecked",76),"type presence/count"),
    ("pahole_overcount",lambda q:q[2]["types"]["rt_mutex_waiter"].__setitem__("completeDefinitionsFound",78),"type presence/count"),
    ("pahole_wrong_present",lambda q:q[2]["types"]["rt_mutex"].__setitem__("completeDefinitionsFound",1),"type presence/count"),
    ("rtmutex_wrong_fw",lambda q:q[3].__setitem__("firmware","OTHER"),"RT-mutex source"),
    ("rtmutex_wrong_sha",lambda q:q[3].__setitem__("samsungSourceHashesVerified",False),"RT-mutex source"),
    ("rtmutex_bug_signal_missing",lambda q:q[3].__setitem__("ownershipMismatchSourcePattern",False),"patch comparison"),
    ("rtmutex_fix_missing",lambda q:q[3].__setitem__("publishedFixDiffsComplete",False),"patch comparison"),
    ("rtmutex_false_exploit",lambda q:q[3].__setitem__("runtimeCveReproduced",True),"improperly"),
    ("rtmutex_false_root",lambda q:q[3].__setitem__("onPhoneRootVerified",True),"improperly"),
    ("rtmutex_false_ksu",lambda q:q[3].__setitem__("kernelSuValidated",True),"improperly"),
    ("rtmutex_false_device",lambda q:q[3].__setitem__("deviceModified",True),"improperly"),
    ("readiness_wrong_profile",lambda q:q[4].__setitem__("profile","different"),"porting identity"),
    ("readiness_payload",lambda q:q[4].__setitem__("payloadPortCompleted",True),"deployable"),
    ("readiness_runtime",lambda q:q[4].__setitem__("ghostLockRuntimeValidated",True),"deployable"),
    ("readiness_root",lambda q:q[4].__setitem__("temporaryRootVerified",True),"deployable"),
    ("readiness_ksu",lambda q:q[4].__setitem__("kernelSuLoaded",True),"deployable"),
    ("readiness_phone",lambda q:q[4].__setitem__("phoneChanged",True),"deployable"),
    ("readiness_feed",lambda q:q[4].__setitem__("includedInProductionFeed",True),"deployable"),
    ("readiness_missing_gate",lambda q:q[4]["gates"].pop(),"nine distinct"),
    ("readiness_stage3_complete",lambda q:q[4]["gates"][2].__setitem__("state","COMPLETE"),"cannot be marked complete"),
    ("readiness_stage4_complete",lambda q:q[4]["gates"][3].__setitem__("state","COMPLETE"),"cannot be marked complete"),
    ("readiness_stage5_complete",lambda q:q[4]["gates"][4].__setitem__("state","COMPLETE"),"cannot be marked complete"),
    ("readiness_stage7_open",lambda q:q[4]["gates"][6].__setitem__("state","OPEN"),"cannot be marked complete"),
    ("readiness_stage8_open",lambda q:q[4]["gates"][7].__setitem__("state","OPEN"),"cannot be marked complete"),
]

for name,modify,pattern in MODIFICATIONS:
    setattr(StageThreeEvidenceTests,"test_"+name,must_fail(name,modify,pattern))


if __name__=="__main__":
    unittest.main()
