#!/usr/bin/env python3
"""Synthetic readelf DWARF direct-member fingerprints, both Clang18 objects."""
from __future__ import annotations
import copy
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from tools import y2q_hxl1_experimental_dwarf_tu_parity as a
from tools import y2q_hxl1_attest_isolated_dwarf_objects as parent

RT=''' <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <10> DW_AT_name : kernel/locking/rtmutex.c
 <1><20>: Abbrev Number: 2 (DW_TAG_structure_type)
    <21> DW_AT_name : (indirect string, offset: 0xa): rt_mutex
    <22> DW_AT_byte_size : 24
 <2><28>: Abbrev Number: 3 (DW_TAG_member)
    <29> DW_AT_name : wait_lock
    <2a> DW_AT_data_member_location : 0
 <2><30>: Abbrev Number: 3 (DW_TAG_member)
    <31> DW_AT_name : owner
    <32> DW_AT_data_member_location : 8
 <1><40>: Abbrev Number: 2 (DW_TAG_structure_type)
    <41> DW_AT_name : rt_mutex_waiter
    <42> DW_AT_byte_size : 48
 <2><48>: Abbrev Number: 3 (DW_TAG_member)
    <49> DW_AT_name : task
    <4a> DW_AT_data_member_location : 0
 <2><50>: Abbrev Number: 3 (DW_TAG_member)
    <51> DW_AT_name : lock
    <52> DW_AT_data_member_location : 8
 <1><58>: Abbrev Number: 4 (DW_TAG_typedef)
    <59> DW_AT_name : unrelated
'''

def two(t1=RT,t2=RT):
    return {list(parent.PINNED_OBJECTS)[0]:a.parse_shapes(t1),
            list(parent.PINNED_OBJECTS)[1]:a.parse_shapes(t2)}

class ShapeTests(unittest.TestCase):
    def test_complete_both(self):
        shapes=a.parse_shapes(RT)
        self.assertEqual(len(shapes["rt_mutex"]),1)
        self.assertEqual(len(shapes["rt_mutex_waiter"]),1)
        self.assertEqual(shapes["rt_mutex"][0]["memberCount"],2)
        self.assertEqual(len(shapes["rt_mutex"][0]["directGeometryFingerprintSha256"]),64)

    def test_same_member_geometry_two_translation_units(self):
        x=a.compare(two())
        self.assertTrue(x["allDirectMemberFingerprintsAgree"])
        self.assertFalse(x["factoryAbiProven"])
        self.assertFalse(x["originalStockStructureOffsetsKnown"])

    def test_different_compilation_unit_die_offsets_are_normalized(self):
        second=RT.replace("<20>","<120>").replace("<28>","<128>")
        self.assertTrue(a.compare(two(RT,second))["allDirectMemberFingerprintsAgree"])

    def test_different_compiler_member_offsets_detected(self):
        second=RT.replace("DW_AT_data_member_location : 8",
                          "DW_AT_data_member_location : 16",1)
        x=a.compare(two(RT,second))
        self.assertFalse(x["allDirectMemberFingerprintsAgree"])
        self.assertFalse(x["factoryAbiProven"])

    def test_different_member_order_detected(self):
        second=RT.replace("DW_AT_name : wait_lock","DW_AT_name : temp") \
                 .replace("DW_AT_name : owner","DW_AT_name : wait_lock") \
                 .replace("DW_AT_name : temp","DW_AT_name : owner")
        self.assertFalse(a.compare(two(RT,second))["allDirectMemberFingerprintsAgree"])

    def test_same_fields_different_nested_tags_not_promoted_to_full_abi(self):
        x=a.compare(two())
        self.assertFalse(x["typeNestedLayoutOrReferencesProven"])
        for v in x["typeChecks"].values():
            self.assertFalse(v["typeReferencesAndNestedLayoutsVerified"])

    def test_incomplete_type_missing_by_byte_size_rejected(self):
        x=RT.replace("DW_AT_byte_size : 24","DW_AT_declaration : 1")
        with self.assertRaisesRegex(a.ShapeError,"exactly one"):
            a.compare(two(RT,x))

    def test_unknown_dwarf_nested_anonymous_member_rejected(self):
        x=RT.replace("DW_AT_name : wait_lock","DW_AT_decl_file : 12")
        with self.assertRaisesRegex(a.ShapeError,"Anonymous"):
            a.parse_shapes(x)

    def test_member_location_expression_is_rejected(self):
        x=RT.replace("DW_AT_data_member_location : 8",
                     "DW_AT_data_member_location : 2 byte block: 23 8 (DW_OP_plus_uconst: 8)",1)
        with self.assertRaisesRegex(a.ShapeError,"Nonconstant"):
            a.parse_shapes(x)

    def test_member_missing_location_rejected(self):
        x=RT.replace("DW_AT_data_member_location : 0",
                     "DW_AT_decl_line : 8",1)
        with self.assertRaisesRegex(a.ShapeError,"Unlocated"):
            a.parse_shapes(x)

    def test_missing_source_member_rejected(self):
        x=RT.replace(" <2><28>: Abbrev Number: 3 (DW_TAG_member)",
                     " <2><28>: Abbrev Number: 3 (DW_TAG_formal_parameter)") \
            .replace(" <2><30>: Abbrev Number: 3 (DW_TAG_member)",
                     " <2><30>: Abbrev Number: 3 (DW_TAG_formal_parameter)")
        with self.assertRaisesRegex(a.ShapeError,"no direct"):
            a.parse_shapes(x)

    def test_missing_both_exact_original_objects_rejected(self):
        x=two()
        x.pop(next(iter(x)))
        with self.assertRaisesRegex(a.ShapeError,"Both exact"):
            a.compare(x)

    def test_extra_dwarf_candidate_rejected(self):
        x=two(RT,RT+RT)
        with self.assertRaisesRegex(a.ShapeError,"exactly one"):
            a.compare(x)

    def test_manufactured_factory_abi_assertion_rejected(self):
        x=two()
        rel=next(iter(x))
        x[rel]["rt_mutex"][0]["factoryAbiEquivalent"]=True
        with self.assertRaisesRegex(a.ShapeError,"Unsupported ABI"):
            a.compare(x)

    def test_unknown_extra_type_ignored(self):
        x=a.parse_shapes(RT+" <1><ac>: Abbrev Number: 2 (DW_TAG_structure_type)\n"
                         " <ad> DW_AT_name : task_struct\n <ae> DW_AT_byte_size : 100\n")
        self.assertEqual(set(x),set(parent.TARGET_TYPES))

    def test_negative_parity_remains_non_deployable(self):
        x=a.compare(two(RT,RT.replace("DW_AT_byte_size : 24",
                         "DW_AT_byte_size : 32")))
        self.assertFalse(x["allDirectMemberFingerprintsAgree"])
        self.assertFalse(x["kernelSuInstalled"])
        self.assertFalse(x["runtimeExploitValidated"])

    def test_markdown_omits_numeric_offsets(self):
        output=a.markdown(a.compare(two()))
        self.assertIn("No factory Clang10",output)
        self.assertNotIn("DW_AT_data_member_location",output)
        self.assertIn("rt_mutex_waiter",output)

    def test_original_static_source_proof_is_invoked(self):
        report=parent.DEFAULT_REPORT
        info={"freshOutput":"/tmp/none"}
        with patch.object(a.owner,"check_source_and_objects",return_value={
            "actualFactoryLayoutProven":False,
            "independentlyRecheckedBuildLogSha256":"f"*64
        }) as callback:
            with patch.object(a.subprocess,"run",side_effect=[
                SimpleNamespace(returncode=0,stdout=RT),
                SimpleNamespace(returncode=0,stdout=RT)
            ]):
                out=a.inspect_originals(info,report)
        self.assertTrue(out["sourceProvenanceVerified"])
        callback.assert_called_once_with(info,report)

    def test_original_static_proof_promoted_to_factory_rejected(self):
        with patch.object(a.owner,"check_source_and_objects",return_value={
            "actualFactoryLayoutProven":True}):
            with self.assertRaisesRegex(a.ShapeError,"elevated"):
                a.inspect_originals({"freshOutput":"/tmp/none"},parent.DEFAULT_REPORT)

    def test_original_readelf_bad_exit_rejected(self):
        with patch.object(a.owner,"check_source_and_objects",return_value={
            "actualFactoryLayoutProven":False}):
            with patch.object(a.subprocess,"run",return_value=SimpleNamespace(
                returncode=1,stdout="")):
                with self.assertRaisesRegex(a.ShapeError,"readelf dump failed"):
                    a.inspect_originals({"freshOutput":"/tmp/none"},parent.DEFAULT_REPORT)

    def test_original_readelf_failure_avoids_factory_claim(self):
        with patch.object(a.owner,"check_source_and_objects",return_value={
            "actualFactoryLayoutProven":False}):
            with patch.object(a.subprocess,"run",side_effect=OSError("readelf absent")):
                with self.assertRaisesRegex(a.ShapeError,"readelf unavailable"):
                    a.inspect_originals({"freshOutput":"/tmp/none"},parent.DEFAULT_REPORT)


if __name__=="__main__":
    unittest.main()
