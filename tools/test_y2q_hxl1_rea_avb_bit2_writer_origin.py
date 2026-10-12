#!/usr/bin/env python3
"""Synthetic-only original HXL1 0x68d08 bit-2 write merge provenance tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_bit2_writer_origin as mod
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


OTHER_SITES=(
    "0x67df8","0x6811c","0x68160","0x68d94","0x68e1c","0x68e24",
    "0x68e3c","0x68e44","0x68e5c","0x68e64","0x68e7c","0x68e84",
    "0x68e9c","0x68ea4","0x68ebc","0x68ec4","0x68ee4","0x68ef0",
    "0x6967c","0x696b8","0x69700","0x69834",
)
HELPER_OWNERS={"0x68810":"0x68810","0x68160":"0x68144",
               "0x69834":"0x69810"}


def native_global_writer():
    base_addr=0x68d08
    ops={hex(base_addr+4*i):"nop" for i in range(133)}
    for addr,m,o in mod.PINNED:
        assert addr in ops
        ops[addr]=m+(" "+o if o else "")
    for addr in mod.STORE_SITES:
        assert addr in ops
        ops[addr]="str w8,[x19,#0x1ec]"
    return evidence_obj("a"*64,"read_function_instructions","procedure",
                        "0x68d08",[a+": "+op for a,op in ops.items()])


def previous():
    original=native_global_writer()
    rows=[]
    for site in OTHER_SITES:
        if site in mod.REMAINING:
            item={"site":site,"nativeOwner":None,
                  "opcodeClass":"NOT_YET_NATIVE_CLASSIFIED"}
        elif site in mod.STORE_SITES:
            item={"site":site,"nativeOwner":mod.ROOT_OWNER,
                  "nativeOpcode":"str","operands":"w8,[x19,#0x1ec]",
                  "opcodeClass":"store-opcode-unattributed"}
        else:
            owner="0x680d8" if site=="0x6811c" else \
                "0x69628" if site.startswith("0x69") else \
                "0x68d08"
            item={"site":site,"nativeOwner":owner,
                  "opcodeClass":"load-opcode-unattributed"}
        rows.append(item)
    return {"sourceAttested":True,"classifiedCount":20,
            "classifiedXrefs":rows,
            "nativeOwnerEvidence":[{"owner":mod.ROOT_OWNER,
                                    "evidenceId":original["evidence_id"]}]}


def function_source(site):
    owner=HELPER_OWNERS[site]
    return evidence_obj("a"*64,"analyze_function","procedure",site,{
        "procedure":{"address":owner,"name":"FUN_"+owner[2:].zfill(8),
                     "body":{"available":True,"ranges":[
                         {"start":owner,"end":hex(int(owner,16)+0x100)}]}},
        "pseudocode":"\n".join([
            "int FUN_original(int param_1, int param_2) {",
            "  iVar1 = FUN_00000048(param_1, param_2);",
            "  if (iVar1 == 1) return 1;",
            "  return 0;",
            "}"]),
        "native_value_flow":{"available":True},
    })


def function_native(site):
    owner=HELPER_OWNERS[site]
    raw={hex(int(owner,16)+4*i):"nop" for i in range(40)}
    raw[site]="mov w0,#0x1" if site!="0x68160" else "ldr w8,[x9,#0x1ec]"
    return evidence_obj("a"*64,"read_function_instructions","procedure",
                        owner,[a+": "+instr for a,instr in raw.items()])


def write_sources(folder,all_cached=False):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/"instructions-bitmask-owner-0x68d08.json").write_text(
        json.dumps(native_global_writer()))
    if all_cached:
        for site in mod.CALL,*mod.REMAINING:
            (folder/("function-bitmask-bit2-"+site+".json")).write_text(
                json.dumps(function_source(site)))
            (folder/("instructions-bitmask-bit2-owner-"+
                     HELPER_OWNERS[site]+".json")).write_text(
                         json.dumps(function_native(site)))


class Hxl1Bit2WriterTests(unittest.TestCase):
    def test_contract_rejects_changed_original_22_xref_count(self):
        contract=mod.check_prior(previous())
        self.assertIn("0x68e24",contract["sites"])
        obj=previous()
        obj["classifiedCount"]=19
        with self.assertRaisesRegex(TriageError,"20/22"):
            mod.check_prior(obj)
        obj=previous()
        obj["classifiedXrefs"][-1]["nativeOwner"]="0x69810"
        with self.assertRaisesRegex(TriageError,"missing native owner"):
            mod.check_prior(obj)

    def test_native_bit2_and_bit3_merge_and_global_address(self):
        facts=mod.native_bit2_merge(
            native_global_writer(),native_global_writer()["evidence_id"])
        self.assertEqual(facts["effectiveAddressFromPinnedX19"],"0x3651ec")
        self.assertEqual(len(facts["storeOpcodeSites"]),7)
        self.assertTrue(facts["exactLocalBit2AndBit3MergeVerified"])
        self.assertFalse(facts["wholeFunctionDominanceVerified"])
        self.assertFalse(facts["authorityOfDecisionSourceVerified"])

    def test_disrupted_0x4_0x8_bitmask_store_rejected(self):
        for original,replacement in (
            ("0x68dfc: mov w8,#0x4","0x68dfc: mov w8,#0x8"),
            ("0x68e18: mov w8,#0x8","0x68e18: mov w8,#0x4"),
            ("0x68e24: str w8,[x19,#0x1ec]","0x68e24: str w8,[x19,#0x1e8]"),
            ("0x68e20: orr w8,w9,w8","0x68e20: and w8,w9,w8"),
        ):
            ev=native_global_writer()
            ev["normalized_result"]=[
                row.replace(original,replacement)
                for row in ev["normalized_result"]]
            with self.subTest(address=original),self.assertRaises(TriageError):
                mod.native_bit2_merge(ev,ev["evidence_id"])

    def test_x19_register_clobber_rejected(self):
        ev=native_global_writer()
        ev["normalized_result"]=[
            line.replace("0x68df0: nop","0x68df0: mov x19,x8")
            for line in ev["normalized_result"]]
        with self.assertRaisesRegex(TriageError,"X19 bitmask-page base overwritten"):
            mod.native_bit2_merge(ev,ev["evidence_id"])

    def test_provider_and_remaining_site_function_attribution(self):
        for site in (mod.CALL,*mod.REMAINING):
            src=mod.source_report(function_source(site),site)
            self.assertEqual(src["owner"],HELPER_OWNERS[site])
            native=mod.original_native_dossier(
                function_native(site),HELPER_OWNERS[site],site)
            self.assertEqual(native["sourceSite"],site)
            self.assertFalse(native["trustedBootStateProven"])

    def test_six_readonly_queries_plan_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            write_sources(root/"rea-security-audit"/"LinuxLoader")
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_clusters",return_value=previous()),\
                 mock.patch.object(mod,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("Host Ghidra executed")):
                result=mod.audit(root)
        self.assertEqual(result["newQueries"],3)
        self.assertEqual(len(result["remainingAndProvider"]),3)
        self.assertFalse(result["bit2SourceAuthorityProven"])
        self.assertFalse(result["deviceModified"])

    def test_cached_queries_reduce_original_runs_to_zero(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            write_sources(root/"rea-security-audit"/"LinuxLoader",all_cached=True)
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(mod,"verify_clusters",return_value=previous()),\
                 mock.patch.object(mod,"choose_targets",return_value=[t]):
                result=mod.audit(root)
        self.assertEqual(result["newQueries"],0)
        self.assertEqual(len(result["remainingAndProvider"]),3)
        self.assertTrue(all(row["native"] for row in result["remainingAndProvider"]))
        self.assertFalse(result["bootloaderUnlockOrOdinBypassProven"])

    def test_no_device_flashing_or_mutation_commands(self):
        source=Path(mod.__file__).read_text()
        for forbidden in ("fastboot flash","heimdall flash","adb shell",
                          "subprocess.Popen(", "os.system("):
            self.assertNotIn(forbidden,source)


if __name__=="__main__":
    unittest.main()
