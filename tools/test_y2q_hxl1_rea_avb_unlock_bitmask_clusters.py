#!/usr/bin/env python3
"""Synthetic-only HXL1 0x3651ec bitmask reference cluster attestation."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import y2q_hxl1_rea_avb_unlock_bitmask_clusters as cluster
from tools import y2q_hxl1_rea_security_audit as base
from tools.test_y2q_hxl1_rea_security_audit import evidence_obj
from tools.y2q_hxl1_bootloader_unlock_audit import TriageError


OWNERS={
    "0x6811c":"0x680e0",
    "0x68d94":"0x68d08",
    "0x6967c":"0x69640",
}
NATIVE_SITES={
    "0x680e0":("0x6811c","0x68160"),
    "0x68d08":("0x68d94","0x68e1c","0x68e24"),
    "0x69640":("0x6967c","0x696b8"),
}


def refs():
    return evidence_obj("a"*64,"xrefs","address",cluster.GLOBAL,
                        list(cluster.SITES))


def fn(seed,owner=None):
    owner=owner or OWNERS[seed]
    pseudo="\n".join([
        f"void FUN_{int(owner,16):08x}(void) {{",
        "  DAT_003651ec = DAT_003651ec & 0xff;",
        "  result = FUN_00012345();",
        "  if (result != 0) { DAT_003651ec = 0; }",
        "}"])
    return evidence_obj("a"*64,"analyze_function","procedure",seed,{
        "procedure":{"address":owner,"name":"FUN_"+owner[2:].zfill(8),
                     "body":{"available":True,"ranges":[
                         {"start":owner,"end":hex(int(owner,16)+0x300)}]}},
        "pseudocode":pseudo,"native_value_flow":{"available":True},
    })


def instructions(entry):
    if entry=="0x67dd8":
        addresses=[hex(0x67dd8+4*i) for i in range(18)]
    else:
        sites=NATIVE_SITES[entry]
        lo=int(entry,16)
        addresses=[hex(lo+4*i) for i in range(200)]
        assert all(site in addresses for site in sites)
    rows=[]
    for addr in addresses:
        if addr=="0x67df8":
            op="ldr w8,[x9,#0x1ec]"
        elif addr=="0x6811c":
            op="adrp x12,0x365000"
        elif addr=="0x68160":
            op="ldr w8,[x12,#0x1ec]"
        elif addr=="0x68d94":
            op="str w3,[x19,#0x1ec]"
        elif addr=="0x68e1c":
            op="add x8,x8,#0x1ec"
        elif addr=="0x6967c":
            op="str w3,[x10,#0x1ec]"
        else:
            op="nop"
        rows.append(addr+": "+op)
    return evidence_obj("a"*64,"read_function_instructions","procedure",
                        entry,rows)


def prior():
    r=refs()
    return {
        "sourceAttested":True,
        "nativeBitmaskSelector":{
            "globalAddress":cluster.GLOBAL,"callerInputMask":4,
            "normalReturnFlowVerified":True,
            "sourceEvidenceId":instructions("0x67dd8")["evidence_id"],
        },
        "sourceXrefs":[{
            "address":cluster.GLOBAL,"xrefCount":len(cluster.SITES),
            "sites":list(cluster.SITES),"displayTruncated":False,
            "originalEvidenceId":r["evidence_id"],
        }],
    }


def store(folder,*,with_owners=False):
    folder.mkdir(parents=True,exist_ok=True)
    (folder/"xrefs-selector-root-0x3651ec.json").write_text(json.dumps(refs()))
    (folder/"instructions-state-boundary-0x67dd8.json").write_text(
        json.dumps(instructions("0x67dd8")))
    if with_owners:
        for seed,owner in OWNERS.items():
            (folder/("function-bitmask-cluster-"+seed+".json")).write_text(
                json.dumps(fn(seed)))
            (folder/("instructions-bitmask-owner-"+owner+".json")).write_text(
                json.dumps(instructions(owner)))


class Hxl1NativeClusterTests(unittest.TestCase):
    def test_exact_22_original_xrefs_fail_closed_on_loss_or_expansion(self):
        result=cluster.verify_inventory(prior())
        self.assertEqual(result["xrefCount"],22)
        damaged=prior()
        damaged["sourceXrefs"][0]["sites"][0]="0x67dfc"
        with self.assertRaisesRegex(TriageError,"22-address"):
            cluster.verify_inventory(damaged)
        damaged=prior()
        damaged["sourceXrefs"][0]["sites"].append("0x69838")
        with self.assertRaisesRegex(TriageError,"22-address"):
            cluster.verify_inventory(damaged)

    def test_full_sha_pinned_original_xref_cache(self):
        r=refs()
        check=cluster.original_xref_audit(r,prior()["sourceXrefs"][0])
        self.assertEqual(check["total"],22)
        bad=refs()
        bad["normalized_result"].remove("0x68d94")
        with self.assertRaisesRegex(TriageError,"Ghidra references changed"):
            cluster.original_xref_audit(bad,prior()["sourceXrefs"][0])

    def test_native_site_opcode_does_not_claim_effective_global_write(self):
        ops=cluster.full_native(instructions("0x68d08"),"0x68d08")
        store=cluster.site_evidence(ops,"0x68d94","0x68d08","ev_synthetic")
        self.assertEqual(store["opcodeClass"],"store-opcode-unattributed")
        self.assertFalse(store["effectiveAddress0x3651ecVerified"])
        self.assertFalse(store["sourceOfStoredValueVerified"])
        addr=cluster.site_evidence(ops,"0x68e1c","0x68d08","ev_synthetic")
        self.assertEqual(addr["opcodeClass"],"address-computation-not-memory-write")

    def test_seed_owner_source_is_containing_function(self):
        res=cluster.original_function(fn("0x6811c"),"0x6811c")
        self.assertEqual(res["owner"],"0x680e0")
        self.assertFalse(res["globalWriterVerified"])
        wrong=fn("0x6811c",owner="0x68200")
        with self.assertRaisesRegex(TriageError,"does not own"):
            cluster.original_function(wrong,"0x6811c")

    def test_plan_mode_uses_only_six_bounded_original_queries(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            store(root/"rea-security-audit"/"LinuxLoader")
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(cluster,"verify_bitmask_producers",
                                   return_value=prior()),\
                 mock.patch.object(cluster,"choose_targets",return_value=[t]),\
                 mock.patch.object(base.subprocess,"Popen",
                                   side_effect=AssertionError("Ghidra must not run")):
                result=cluster.audit(root)
        self.assertEqual(result["newQueries"],3)
        self.assertEqual(result["classifiedCount"],1)
        self.assertEqual(len(result["classifiedXrefs"]),22)
        self.assertFalse(result["globalWriteProven"])
        self.assertFalse(result["deviceModified"])

    def test_all_three_clusters_cached_resolve_original_xref_owners(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            store(root/"rea-security-audit"/"LinuxLoader",with_owners=True)
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(cluster,"verify_bitmask_producers",
                                   return_value=prior()),\
                 mock.patch.object(cluster,"choose_targets",return_value=[t]):
                result=cluster.audit(root)
        self.assertEqual(result["newQueries"],0)
        self.assertEqual(len(result["sourceOwners"]),3)
        self.assertGreater(result["classifiedCount"],3)
        self.assertEqual(result["classifiedXrefs"][0]["nativeOwner"],"0x67dd8")
        self.assertFalse(result["bit2ProducerAndTrustProven"])

    def test_missing_native_site_stays_unclassified(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            store(root/"rea-security-audit"/"LinuxLoader",with_owners=True)
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            with mock.patch.object(cluster,"verify_bitmask_producers",
                                   return_value=prior()),\
                 mock.patch.object(cluster,"choose_targets",return_value=[t]):
                r=cluster.audit(root)
        candidate=next(x for x in r["classifiedXrefs"] if x["site"]=="0x68ef0")
        self.assertEqual(candidate["opcodeClass"],"NOT_YET_NATIVE_CLASSIFIED")
        self.assertFalse(candidate["reachableStoreToGlobalVerified"])

    def test_cached_original_reader_provenance_mismatch_halts(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            store(root/"rea-security-audit"/"LinuxLoader")
            t=base.Target("LinuxLoader",root/"LinuxLoader-HXL1.efi","a"*64,{})
            modified=prior()
            modified["nativeBitmaskSelector"]["sourceEvidenceId"]="ev_fake"
            with mock.patch.object(cluster,"verify_bitmask_producers",
                                   return_value=modified),\
                 mock.patch.object(cluster,"choose_targets",return_value=[t]):
                with self.assertRaisesRegex(TriageError,"Evidence differs"):
                    cluster.audit(root)

    def test_no_untrusted_execution_device_or_flash(self):
        s=Path(cluster.__file__).read_text()
        for banned in ("fastboot flash","heimdall flash","adb shell",
                       "subprocess.Popen(", "os.system("):
            self.assertNotIn(banned,s)


if __name__=="__main__":
    unittest.main()
