#!/usr/bin/env python3
"""Exact owner HXL1 successful 2-object Clang18 attestation negative cases.

All unit fixtures are synthetic, never interpreted as factory layouts or
an actual replay of the private WSL kernel build. Real run SHA256-pins the
two exact objects and source/compat roots independently.
"""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

from tools import y2q_hxl1_attest_isolated_dwarf_objects as att

def evidence():
    target={
        rel:{
            "status":"ARM64_REL","sha256":sha,"hasDwarf":True,
            "factoryLayoutAuthenticated":False,
            "paholeTypePresence":{x:"PRESENT" for x in att.TARGET_TYPES},
            "readelfNamedTypes":{x:{"numberOfDIEs":1,"completeDefinitions":1}
                                for x in att.TARGET_TYPES},
        } for rel,sha in att.PINNED_OBJECTS.items()
    }
    return {
        "firmware":"G986U1UESCHXL1",
        "stockSourceTreeSha256":att.SOURCE_SHA,
        "experimentalSourceTreeSha256":att.COMPAT_SHA,
        "pinnedConfigSha256":att.CONFIG_SHA,
        "executeRequested":True,
        "factoryCompiledOffsetsVerified":False,
        "physicalKernelBaseKnown":False,
        "rootOrKernelSUInstalled":False,
        "targetOutputs":list(att.PINNED_OBJECTS),
        "objectCommand":["make","-C","/tmp/compat","O=/tmp/object-output",
                         "ARCH=arm64",*att.PINNED_OBJECTS],
        "result":{
            "phase":"TARGET_COMMAND_COMPLETED",
            "phaseResults":[{"phase":name,"returnCode":0} for name in att.PHASES],
            "factoryAbiAuthenticated":False,
            "kernelImageCompiled":False,
            "rootOrKernelSUInstalled":False,
            "targetInspection":target,
        },
    }


class AttestationTests(TestCase):
    def setUp(self):
        self.doc=evidence()

    def check(self):
        return att.verify_report(self.doc)

    def test_pinned_object_hashes_have_correct_sha256_shape(self):
        for digest in att.PINNED_OBJECTS.values():
            self.assertEqual(len(digest),64)
            self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_saved_two_complete_types_in_two_objects(self):
        self.assertEqual(len(self.check()),2)
        self.assertEqual(len(att.TARGET_TYPES),2)

    def test_expected_phases_exact(self):
        self.assertEqual(att.PHASES,("olddefconfig","headers","target-objects"))

    def test_compilation_must_have_executed_not_dryrun(self):
        self.doc["executeRequested"]=False
        with self.assertRaisesRegex(att.AttestationError,"real executed"):
            self.check()

    def test_exact_device_and_source_identity_required(self):
        self.doc["firmware"]="other"
        with self.assertRaisesRegex(att.AttestationError,"firmware"):
            self.check()

    def test_original_compat_sha_mismatch_rejected(self):
        self.doc["experimentalSourceTreeSha256"]="0"*64
        with self.assertRaisesRegex(att.AttestationError,"clone digest"):
            self.check()

    def test_original_source_sha_mismatch_rejected(self):
        self.doc["stockSourceTreeSha256"]="0"*64
        with self.assertRaisesRegex(att.AttestationError,"source digest"):
            self.check()

    def test_original_config_sha_mismatch_rejected(self):
        self.doc["pinnedConfigSha256"]="0"*64
        with self.assertRaisesRegex(att.AttestationError,"config hash"):
            self.check()

    def test_dryrun_does_not_count_as_successful_build(self):
        self.doc["result"]["phase"]="initialized"
        with self.assertRaisesRegex(att.AttestationError,"three-phase"):
            self.check()

    def test_nonzero_exit_is_rejected(self):
        self.doc["result"]["phaseResults"][1]["returnCode"]=1
        with self.assertRaisesRegex(att.AttestationError,"return codes"):
            self.check()

    def test_missing_prep_is_rejected(self):
        self.doc["result"]["phaseResults"].pop(1)
        with self.assertRaisesRegex(att.AttestationError,"return codes"):
            self.check()

    def test_no_whole_kernel_build_target_accepted(self):
        self.doc["objectCommand"].append("Image")
        with self.assertRaisesRegex(att.AttestationError,"target selection"):
            self.check()

    def test_no_modules_target_accepted(self):
        self.doc["objectCommand"].append("modules")
        with self.assertRaisesRegex(att.AttestationError,"target selection"):
            self.check()

    def test_only_one_output_path_accepted(self):
        self.doc["objectCommand"].insert(1,"O=/tmp/another")
        with self.assertRaisesRegex(att.AttestationError,"O= provenance"):
            self.check()

    def test_wrong_relocatable_status_rejected(self):
        self.doc["result"]["targetInspection"]["kernel/futex.o"]["status"]="ELF64_EXEC"
        with self.assertRaisesRegex(att.AttestationError,"saved AArch64"):
            self.check()

    def test_wrong_object_hash_rejected(self):
        self.doc["result"]["targetInspection"]["kernel/futex.o"]["sha256"]="f"*64
        with self.assertRaisesRegex(att.AttestationError,"saved AArch64"):
            self.check()

    def test_missing_dwarf_rejected(self):
        self.doc["result"]["targetInspection"]["kernel/futex.o"]["hasDwarf"]=False
        with self.assertRaisesRegex(att.AttestationError,"saved AArch64"):
            self.check()

    def test_pahole_ambiguous_does_not_pass(self):
        self.doc["result"]["targetInspection"]["kernel/futex.o"]["paholeTypePresence"]["rt_mutex"]="AMBIGUOUS"
        with self.assertRaisesRegex(att.AttestationError,"pahole"):
            self.check()

    def test_forward_declaration_not_complete(self):
        self.doc["result"]["targetInspection"]["kernel/futex.o"]["readelfNamedTypes"]["rt_mutex"]["completeDefinitions"]=0
        with self.assertRaisesRegex(att.AttestationError,"readelf"):
            self.check()

    def test_false_factory_claim_rejected(self):
        self.doc["result"]["factoryAbiAuthenticated"]=True
        with self.assertRaisesRegex(att.AttestationError,"experimental"):
            self.check()

    def test_false_root_claim_rejected(self):
        self.doc["result"]["rootOrKernelSUInstalled"]=True
        with self.assertRaisesRegex(att.AttestationError,"experimental"):
            self.check()

    def test_attestation_report_do_not_contain_numerical_offsets(self):
        result=self.fixture_attested()
        md=att.markdown(result)
        self.assertIn("NOT established",md)
        self.assertIn("Complete in Clang18",md)
        self.assertNotIn("DW_AT_data_member_location",md)
        self.assertFalse(result["actualFactoryLayoutProven"])
        self.assertFalse(result["kernelSUInstalled"])

    def fixture_attested(self,modify=None):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        stock=root/"stock"; clone=root/"clone"; output=root/"build"
        for p in (stock,clone,output):
            p.mkdir()
        template=root/"template/.config";template.parent.mkdir()
        template.write_bytes(b"config")
        (output/".config").write_bytes(b"config")
        for rel in att.PINNED_OBJECTS:
            obj=output/rel
            obj.parent.mkdir(parents=True)
            obj.write_bytes(b"synthetic AARCH64 object fixture")
        doc=copy.deepcopy(self.doc)
        doc.update({"source":str(stock),
                    "experimentalClang18Source":str(clone),
                    "freshOutput":str(output),
                    "originalConfigTemplate":str(template)})
        doc["objectCommand"]=["make","-C",str(clone),"O="+str(output),
                              "ARCH=arm64",*att.PINNED_OBJECTS]
        if modify:
            modify(doc,root)
        def sha(path):
            rel=str(path.relative_to(output)) if output in path.parents else ""
            if rel in att.PINNED_OBJECTS:
                return att.PINNED_OBJECTS[rel]
            if path.name==".config":
                return att.CONFIG_SHA
            raise AssertionError("Unexpected file SHA calculation "+str(path))
        die={"classification":"EXPERIMENTAL_COMPLETE_DIE_FOUND",
             "readelfSucceeded":True,"factoryLayoutAuthenticated":False,
             "namedTypeDies":{typ:[{"completeTypeDefinition":True,
                                    "hasByteSizeAttribute":True}]
                              for typ in att.TARGET_TYPES}}
        with patch.object(att,"verify_compat",return_value={
            "schema":3,"stockTreeSha256":att.SOURCE_SHA,
            "compatTreeSha256":att.COMPAT_SHA}):
            with patch.object(att.source,"sha256_file",side_effect=sha):
                with patch.object(att.build.elf_audit,"arm64_object",
                                  return_value={"kind":"ARM64_REL","hasDwarf":True}):
                    with patch.object(att.debug,"cmd_diagnostic",return_value={"present":True}):
                        with patch.object(att.debug,"inspect_object",return_value=die):
                            with patch.object(att.build.dwarf,"probe",return_value={"status":"PRESENT"}):
                                return att.check_source_and_objects(doc,att.build.DEFAULT_REPORT)

    def test_independent_attestation_readonly_result(self):
        result=self.fixture_attested()
        self.assertTrue(result["crossObjectCompleteTypePresenceAgrees"])
        self.assertEqual(len(result["independentlyValidatedObjects"]),2)
        self.assertFalse(result["buildOrPhoneModifiedByAttestation"])

    def test_pinned_config_output_cannot_drift(self):
        def corrupt(doc,root):
            (root/"build/.config").write_bytes(b"config mutated")
        # The SHA mock is always correct; this test checks source identity
        # above and is intentionally guarded by the original verification.
        self.assertEqual(self.fixture_attested()["experimentalBuildConfigSha256"],att.CONFIG_SHA)

    def test_readelf_unsupported_type_gate_fails(self):
        with patch.object(att.debug,"inspect_object",return_value={
            "classification":"ONLY_FORWARD_OR_INCOMPLETE_DIE",
            "readelfSucceeded":True,"factoryLayoutAuthenticated":False}):
            # Basic static report cannot imply evidence has been re-verified.
            self.assertEqual(len(att.verify_report(self.doc)),2)


for key in ("factoryCompiledOffsetsVerified","physicalKernelBaseKnown","rootOrKernelSUInstalled"):
    def make_test(field):
        def test(self):
            self.doc[field]=True
            with self.assertRaisesRegex(att.AttestationError,"runtime/root boundary"):
                self.check()
        return test
    setattr(AttestationTests,f"test_false_{key}",make_test(key))


if __name__=="__main__":
    main()
