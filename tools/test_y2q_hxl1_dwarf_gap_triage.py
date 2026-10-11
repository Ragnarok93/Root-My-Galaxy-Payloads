#!/usr/bin/env python3
"""Offline regression of independent readelf RT-mutex DWARF gap diagnosis.

Tests no kernel exploit, runtime offsets or build modification. The parser
is tested against realistic readelf --debug-dump=info text, multiple CUs,
forward declarations, alternate string encodings and nested DIEs.
"""
from __future__ import annotations
import copy
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from tools import y2q_hxl1_dwarf_gap_triage as t

FULL_DIES="""Compilation Unit @ offset 0:
 <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <e>   DW_AT_name : kernel/locking/rtmutex.c
 <1><2c>: Abbrev Number: 2 (DW_TAG_structure_type)
    <2d>   DW_AT_name : (indirect string, offset: 0x530): rt_mutex
    <2e>   DW_AT_byte_size : 24
 <2><40>: Abbrev Number: 3 (DW_TAG_member)
    <41>   DW_AT_name : wait_lock
    <43>   DW_AT_data_member_location: 0
 <1><80>: Abbrev Number: 2 (DW_TAG_structure_type)
    <81>   DW_AT_name : rt_mutex_waiter
    <82>   DW_AT_byte_size : 56
 <2><95>: Abbrev Number: 3 (DW_TAG_member)
    <96>   DW_AT_name : task
 <1><ab>: Abbrev Number: 4 (DW_TAG_pointer_type)
"""
FORWARD_DIES=""" <1><2c>: Abbrev Number: 2 (DW_TAG_structure_type)
    <2d> DW_AT_name : (indirect string, offset: 0x530): rt_mutex
    <2e> DW_AT_declaration : 1
 <1><37>: Abbrev Number: 2 (DW_TAG_structure_type)
    <38> DW_AT_name : rt_mutex_waiter
    <39> DW_AT_declaration : 1
"""
NO_RT=""" <1><2c>: Abbrev Number: 2 (DW_TAG_structure_type)
    <2d> DW_AT_name : rt_mutex_unrelated
    <2e> DW_AT_byte_size : 24
 <1><38>: Abbrev Number: 2 (DW_TAG_structure_type)
    <39> DW_AT_name : task_struct
    <3a> DW_AT_byte_size : 128
"""
def elf_with_dwarf()->bytes:
    """Minimal well-formed ARM64 ELF64 ET_REL with real .debug section names."""
    from tools.test_y2q_partial_samsung_dwarf_audit import fake_arm64_debug_object
    return fake_arm64_debug_object()

def base_reports():
    proof={
        "device":{"model":t.stage3.TARGET,"firmware":t.stage3.FIRMWARE,
                  "kernel":t.stage3.RELEASE},
        "decisions":{
            "originalCompiledStructureOffsetsVerified":False,
            "ghostLockRuntimeApplicable":False,
            "kernelSuCompatibleAndAuthorized":False,
        },
        "checks":{"rtMutexTypePresence":{
            name:{"completeDefinitionsFound":0}
            for name in t.TARGET_TYPES}},
    }
    provisional={
        "target":f"{t.stage3.TARGET} {t.stage3.FIRMWARE}",
        "buildConfigSha256":t.objects.GENERATED_SHA,
        "originalHashPinsMatched":True,
        "objectCount":85,"arm64RelCount":77,
        "arm64DwarfCount":72,
        "selected":{name:{"kind":"NOT_PRESENT"} for name in t.SELECTED_OBJECTS},
    }
    return proof,provisional

class TypeDIEParserTests(unittest.TestCase):
    def test_both_complete_structs(self):
        x=t.parse_named_struct_dies(FULL_DIES)
        self.assertEqual(set(x),set(t.TARGET_TYPES))
        self.assertTrue(x["rt_mutex"][0]["completeTypeDefinition"])
        self.assertTrue(x["rt_mutex_waiter"][0]["completeTypeDefinition"])

    def test_nested_member_attributes_do_not_poison_parent(self):
        x=t.parse_named_struct_dies(FULL_DIES)
        self.assertEqual(len(x["rt_mutex"]),1)
        self.assertEqual(len(x["rt_mutex_waiter"]),1)
        self.assertNotIn("wait_lock",str(x))

    def test_forward_declarations_are_not_complete(self):
        x=t.parse_named_struct_dies(FORWARD_DIES)
        self.assertFalse(x["rt_mutex"][0]["completeTypeDefinition"])
        self.assertFalse(x["rt_mutex_waiter"][0]["completeTypeDefinition"])

    def test_lookalike_names_are_ignored(self):
        x=t.parse_named_struct_dies(NO_RT)
        self.assertEqual(x,{"rt_mutex":[],"rt_mutex_waiter":[]})

    def test_no_source_does_not_claim_missing_factory_types(self):
        self.assertEqual(t.parse_named_struct_dies(""),{
            "rt_mutex":[],"rt_mutex_waiter":[]})

    def test_indirect_dwarf_string_is_exact_match(self):
        txt=FULL_DIES.replace("rt_mutex\n","rt_mutex_something\n")
        x=t.parse_named_struct_dies(txt)
        self.assertEqual(x["rt_mutex"],[])

    def test_type_needing_byte_size_remains_incomplete(self):
        txt=FULL_DIES.replace("DW_AT_byte_size : 24","DW_AT_alignment : 8")
        self.assertFalse(t.parse_named_struct_dies(txt)["rt_mutex"][0]
                         ["completeTypeDefinition"])

    def test_explicit_declaration_takes_priority_over_byte_size(self):
        txt=FULL_DIES.replace("DW_AT_byte_size : 24",
                              "DW_AT_byte_size : 24\n <2f> DW_AT_declaration : 1")
        self.assertFalse(t.parse_named_struct_dies(txt)["rt_mutex"][0]
                         ["completeTypeDefinition"])

    def test_multi_compilation_unit_has_two_entries(self):
        x=t.parse_named_struct_dies(FULL_DIES+"\n"+FULL_DIES)
        self.assertEqual(len(x["rt_mutex"]),2)

    def test_split_dwarf_specification_without_size_unverified(self):
        x=t.parse_named_struct_dies(
            " <1><22>: Abbrev Number: 3 (DW_TAG_structure_type)\n"
            " <23> DW_AT_name : rt_mutex\n"
            " <24> DW_AT_specification : <0xabc>\n")
        self.assertFalse(x["rt_mutex"][0]["completeTypeDefinition"])
        self.assertTrue(x["rt_mutex"][0]["hasSpecificationReference"])

    def test_dwarf_class_type_is_not_conflated_with_string(self):
        raw=" <1><22>: Abbrev Number: 3 (DW_TAG_class_type)\n"
        raw+=" <23> DW_AT_name : rt_mutex\n <24> DW_AT_byte_size : 32\n"
        x=t.parse_named_struct_dies(raw)
        self.assertEqual(x["rt_mutex"][0]["kind"],"DW_TAG_class_type")

    def test_multiple_repeated_die_declarations(self):
        raw=FORWARD_DIES+"\n"+FULL_DIES
        x=t.parse_named_struct_dies(raw)
        self.assertEqual(len(x["rt_mutex"]),2)
        self.assertTrue(any(y["completeTypeDefinition"] for y in x["rt_mutex"]))

    def test_does_not_export_struct_sizes_or_member_offsets(self):
        txt=str(t.parse_named_struct_dies(FULL_DIES))
        self.assertNotIn("member_location",txt)
        self.assertNotIn("'size':",txt)

class ObjectFlagTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.build=Path(temp.name)
        self.target="kernel/locking/rtmutex.o"
        self.obj=self.build/self.target
        self.obj.parent.mkdir(parents=True)
        self.obj.write_bytes(elf_with_dwarf())
        self.cmd=self.obj.with_name("."+self.obj.name+".cmd")

    def test_no_cmd_file_reported_not_invented(self):
        self.assertFalse(t.cmd_diagnostic(self.build,self.target)["present"])

    def test_full_g4_debug_info_flag(self):
        self.cmd.write_text("cmd_kernel/locking/rtmutex.o := clang -g -gdwarf-4 -c rtmutex.c")
        f=t.cmd_diagnostic(self.build,self.target)["debugSwitches"]
        self.assertTrue(f["fullDebugMinusG"])
        self.assertTrue(f["dwarfVersion4"])
        self.assertFalse(f["lineTablesOnly"])

    def test_line_tables_only_detected_independently(self):
        self.cmd.write_text("cmd := clang -gline-tables-only -c rtmutex.c")
        f=t.cmd_diagnostic(self.build,self.target)["debugSwitches"]
        self.assertTrue(f["lineTablesOnly"])
        self.assertFalse(f["fullDebugMinusG"])

    def test_no_debug_and_split_type_filters(self):
        self.cmd.write_text("cmd := clang -g0 -fno-standalone-debug -gsplit-dwarf")
        f=t.cmd_diagnostic(self.build,self.target)["debugSwitches"]
        self.assertTrue(f["noDebug"])
        self.assertTrue(f["debugTypesPruned"])
        self.assertTrue(f["splitDwarf"])

    def test_zero_flags_stay_false(self):
        self.cmd.write_text("cmd := clang -O2 -c rtmutex.c")
        self.assertFalse(any(t.cmd_diagnostic(self.build,self.target)
                             ["debugSwitches"].values()))

    def test_object_symlink_is_refused(self):
        self.obj.unlink()
        original=self.build/"other"
        original.write_bytes(elf_with_dwarf())
        self.obj.symlink_to(original)
        self.assertEqual(t.inspect_object(self.build,self.target)
                         ["classification"],"SYMLINK_REFUSED")

    def test_cmd_symlink_is_refused(self):
        actual=self.build/"cmd"
        actual.write_text("clang -g")
        self.cmd.symlink_to(actual)
        with self.assertRaisesRegex(t.GapError,"symlinked"):
            t.cmd_diagnostic(self.build,self.target)

    def test_missing_selected_object(self):
        self.obj.unlink()
        self.assertEqual(t.inspect_object(self.build,self.target)
                         ["classification"],"OBJECT_MISSING")

    def test_object_elf_missing_debug_info(self):
        with patch.object(t.objects,"arm64_object",return_value={
            "kind":"ARM64_REL","hasDwarf":False,"debugSections":[]}):
            out=t.inspect_object(self.build,self.target)
        self.assertEqual(out["classification"],"ELF_WITHOUT_DWARF_INFO")

    def test_non_aarch64_file_classified(self):
        with patch.object(t.objects,"arm64_object",return_value={"kind":"NOT_ELF"}):
            x=t.inspect_object(self.build,self.target)
        self.assertEqual(x["classification"],"NOT_ARM64_RELOCATABLE")

    def readelf(self,text,returncode=0):
        with patch.object(t.objects,"arm64_object",return_value={
            "kind":"ARM64_REL","hasDwarf":True,"debugSections":[".debug_info"]}):
            with patch.object(t.subprocess,"run",return_value=SimpleNamespace(
                stdout=text,stderr="",returncode=returncode)):
                return t.inspect_object(self.build,self.target)

    def test_readelf_identifies_complete_experimental_type(self):
        x=self.readelf(FULL_DIES)
        self.assertEqual(x["classification"],"EXPERIMENTAL_COMPLETE_DIE_FOUND")
        self.assertFalse(x["factoryLayoutAuthenticated"])

    def test_readelf_finds_only_forward_declarations(self):
        x=self.readelf(FORWARD_DIES)
        self.assertEqual(x["classification"],"ONLY_FORWARD_OR_INCOMPLETE_DIE")

    def test_readelf_nothing_named(self):
        x=self.readelf(NO_RT)
        self.assertEqual(x["classification"],
                         "NO_NAMED_RT_MUTEX_DIE_IN_RETAINED_OBJECT")

    def test_readelf_nonzero_is_not_a_negative_type_finding(self):
        x=self.readelf("broken",returncode=2)
        self.assertEqual(x["classification"],"READELF_TOOL_ERROR")

    def test_readelf_timeout_preserved_as_error(self):
        import subprocess
        with patch.object(t.objects,"arm64_object",return_value={
            "kind":"ARM64_REL","hasDwarf":True}):
            with patch.object(t.subprocess,"run",side_effect=subprocess.TimeoutExpired(
                "readelf",2)):
                x=t.inspect_object(self.build,self.target)
        self.assertEqual(x["classification"],"READELF_TOOL_ERROR")

    def test_readelf_output_too_large_not_negative_type(self):
        with patch.object(t,"MAX_DEBUG_OUTPUT",4):
            x=self.readelf(FULL_DIES)
        self.assertEqual(x["classification"],"DEBUG_DUMP_EXCEEDS_BOUND")

    def test_original_object_not_modified(self):
        before=self.obj.read_bytes()
        self.readelf(FULL_DIES)
        self.assertEqual(self.obj.read_bytes(),before)

class ParentMatrixIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.proof,self.partial=base_reports()
        self.build=Path("/does-not-exist")

    def evaluate(self):
        with patch.object(t,"inspect_object",side_effect=lambda _,name:{
            "relativePath":name,
            "classification":"OBJECT_MISSING",
            "experimentalOnly":True,"factoryLayoutAuthenticated":False
        }):
            return t.audit(self.build,self.proof,self.partial)

    def test_all_six_selected_objects_triaged(self):
        x=self.evaluate()
        self.assertEqual(len(x["selectedObjectDiagnostics"]),6)
        self.assertEqual(x["partialBuildArm64ObjectsWithDwarf"],72)

    def test_no_root_offsets_or_installable_ksu(self):
        x=self.evaluate()
        self.assertFalse(x["fullOriginalFactoryAbiEstablished"])
        self.assertFalse(x["useForNativeExploitOffsets"])
        self.assertFalse(x["kernelSuInstallable"])
        self.assertFalse(x["rootDemonstrated"])

    def test_matrix_provenance_wins_over_local_presence(self):
        self.proof["decisions"]["originalCompiledStructureOffsetsVerified"]=True
        with self.assertRaisesRegex(t.GapError,"illegally"):
            self.evaluate()

    def test_unverified_exploit_cannot_be_promoted(self):
        self.proof["decisions"]["ghostLockRuntimeApplicable"]=True
        with self.assertRaisesRegex(t.GapError,"illegally"):
            self.evaluate()

    def test_unverified_ksu_cannot_be_promoted(self):
        self.proof["decisions"]["kernelSuCompatibleAndAuthorized"]=True
        with self.assertRaisesRegex(t.GapError,"illegally"):
            self.evaluate()

    def test_partial_compiler_wrong_sha_fails(self):
        self.partial["buildConfigSha256"]="f"*64
        with self.assertRaisesRegex(t.GapError,"not authenticated"):
            self.evaluate()

    def test_missing_selected_object_status_fails(self):
        del self.partial["selected"]["kernel/futex.o"]
        with self.assertRaisesRegex(t.GapError,"Missing expected"):
            self.evaluate()

    def test_missing_pahole_result_fails(self):
        del self.proof["checks"]["rtMutexTypePresence"]["rt_mutex"]
        with self.assertRaisesRegex(t.GapError,"incomplete"):
            self.evaluate()

    def test_report_expressly_marks_provisional_types(self):
        r=t.markdown(self.evaluate())
        self.assertIn("Clang18",r)
        self.assertIn("No numerical member offsets",r)
        self.assertIn("kernel/locking/rtmutex.o",r)


if __name__=="__main__":
    unittest.main()
