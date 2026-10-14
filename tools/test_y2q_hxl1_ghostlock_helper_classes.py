"""Fail-closed HXL1 sendmsg branch-label and JOP-trampoline regression tests."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import y2q_hxl1_ghostlock_helper_classes as m

ADDRESSES={
  "__stack_chk_fail":"0xffffff80080b9524",
  "__kmalloc":"0xffffff80082af0e4",
  "kfree":"0xffffff80082af6d4",
  "__check_object_size":"0xffffff80082d571c",
  "fput":"0xffffff80082df814",
  "__fdget":"0xffffff8008305c0c",
  "security_socket_sendmsg":"0xffffff8008503bcc",
  "import_iovec":"0xffffff80085cc7bc",
  "import_single_range":"0xffffff80085cc97c",
  "move_addr_to_kernel":"0xffffff800966c884",
  "___sys_sendmsg":"0xffffff800966f2a4",
  "copy_msghdr_from_user":"0xffffff800967357c",
  "sock_kmalloc":"0xffffff80096774c4",
  "sock_kfree_s":"0xffffff8009677554",
  "get_compat_msghdr":"0xffffff80096d3f6c",
  "cmsghdr_from_user_compat_to_kern":"0xffffff80096d40fc",
  "__arch_copy_from_user":"0xffffff8009949a00",
  "__pi_memcmp":"0xffffff800994a4d4",
  "__memcpy|__pi_memcpy":"0xffffff800994a6c0",
  "__memset|__pi_memset":"0xffffff800994a9c0",
  "jopp_springboard_blr_x8":"0xffffff800997463c",
}
def labels(label):
    return label.split("|")

def fixture():
    """Generate exactly the observed label/caller counts and verified internal edges."""
    targets=[
        {"targetStaticVA":va,"status":"EXACT_RECOVERED_TEXT_LABEL",
         "labels":labels(name),"totalIncomingCalls":m.LABEL_COUNTS[name],
         "calleeCompilerFunctionIdentityVerified":False}
        for name,va in ADDRESSES.items()
    ]
    caller_slots=[]
    for name,n in m.EXPECTED_CALLER_COUNTS.items():
        caller_slots.extend([name]*n)
    reserved=[
        ("__sys_sendmsg","0xffffff800966f248","___sys_sendmsg"),
        ("__sys_sendmmsg","0xffffff800966f750","___sys_sendmsg"),
        ("__sys_sendmmsg","0xffffff800966f7d4","___sys_sendmsg"),
        ("___sys_sendmsg","0xffffff800966f304","copy_msghdr_from_user"),
    ]
    edges=[]
    for caller,site,label in reserved:
        edges.append({"caller":caller,"callStaticVA":site,
                      "targetStaticVA":ADDRESSES[label],
                      "targetLabelMatch":"EXACT_RECOVERED_TEXT_LABEL",
                      "targetLabels":labels(label),
                      "registerArgumentsTraced":False})
        caller_slots.remove(caller)
    remaining=dict(m.LABEL_COUNTS)
    for _,_,label in reserved:
        remaining[label]-=1
    seq=0
    for label,amount in remaining.items():
        for _ in range(amount):
            caller=caller_slots.pop(0)
            site=f"0x{0xffffff8008081000+seq*4:016x}"
            seq+=1
            edges.append({"caller":caller,"callStaticVA":site,
                          "targetStaticVA":ADDRESSES[label],
                          "targetLabelMatch":"EXACT_RECOVERED_TEXT_LABEL",
                          "targetLabels":labels(label),
                          "registerArgumentsTraced":False})
    assert len(edges)==41 and not caller_slots and seq==37
    d={"schemaVersion":1,"target":"SM-G986U1/G986U1UESCHXL1",
       "scope":"STATIC_ORIGINAL_SENDMSG_CALLS_TO_RECOVERED_NM_LABELS_ONLY",
       "nmSha256":m.EXPECTED_NM,
       "stockImageSha256ReportedByEarlierAttestor":m.EXPECTED_KERNEL,
       "callsites":41,"uniqueDestinations":21,
       "exactSymbolDestinations":21,"uncertainInteriorDestinations":0,
       "directTargets":targets,"callEdges":edges}
    for field in ("calleeSourceFunctionIdentityVerified",
                  "callArgumentPointerDataflowVerified",
                  "sendmsgFutexWaiterLifetimeOverlapVerified",
                  "originalKernelPhysicalLoadBaseVerified",
                  "liveGhostLockExploitVerified",
                  "rootOrKernelSuVerified","deviceModified"):
        d[field]=False
    return d

class HelperClassesTests(unittest.TestCase):
    def test_full_41_site_categorization_without_runtime_claim(self):
        r=m.summarize(fixture())
        self.assertEqual(r["staticCallsites"],41)
        self.assertEqual(r["distinctImmediateBranchDestinations"],21)
        self.assertEqual(sum(r["staticCallsitesByHelperClass"].values()),41)
        self.assertEqual(r["branchToNamedJopTrampolineCount"],3)
        self.assertEqual(r["stackProtectorFailureBranchSites"],5)
        self.assertFalse(r["mallocFreeObjectPairingProven"])
        self.assertFalse(r["futexWaiterSendmsgStackAliasVerified"])

    def test_three_jop_trampoline_edges_are_not_final_callees(self):
        report=m.summarize(fixture())
        self.assertEqual(len(report["jopTrampolineSites"]),3)
        self.assertFalse(report["effectiveCalleeResolvedForJopTrampoline"])
        self.assertTrue(all(x["effectiveCalleeIdentified"] is False and
                            x["x8RegisterTargetProven"] is False
                            for x in report["jopTrampolineSites"]))

    def test_aliases_preserved_as_one_recovered_address(self):
        r=m.summarize(fixture())
        self.assertEqual(r["staticCallsitesByRecoveredLabel"]["__memcpy|__pi_memcpy"],1)
        self.assertEqual(r["staticCallsitesByRecoveredLabel"]["__memset|__pi_memset"],3)

    def test_premature_pointer_flow_claim_rejected(self):
        d=fixture()
        d["callEdges"][0]["registerArgumentsTraced"]=True
        with self.assertRaisesRegex(m.Gate,"argument proof"):
            m.summarize(d)

    def test_bad_21_label_identity_rejected(self):
        d=fixture()
        item=next(x for x in d["directTargets"] if x["labels"]==["kfree"])
        item["labels"]=["kmalloc"]
        with self.assertRaisesRegex(m.Gate,"inventory drift"):
            m.summarize(d)

    def test_changed_frequency_rejected(self):
        d=fixture()
        item=next(x for x in d["directTargets"] if x["labels"]==["__kmalloc"])
        item["totalIncomingCalls"]=5
        with self.assertRaisesRegex(m.Gate,"count drift"):
            m.summarize(d)

    def test_removed_known_sendmsg_edge_rejected(self):
        d=fixture()
        item=next(x for x in d["callEdges"] if x["callStaticVA"]=="0xffffff800966f248")
        item["callStaticVA"]="0xffffff800966f240"
        with self.assertRaisesRegex(m.Gate,"call edges lost"):
            m.summarize(d)

    def test_changed_stock_nm_digest_fails(self):
        d=fixture();d["nmSha256"]="0"*64
        with self.assertRaisesRegex(m.Gate,"provenance"):
            m.summarize(d)

    def test_duplicate_edge_rejected(self):
        d=fixture()
        d["callEdges"][1]["callStaticVA"]=d["callEdges"][0]["callStaticVA"]
        d["callEdges"][1]["caller"]=d["callEdges"][0]["caller"]
        d["callEdges"][1]["targetStaticVA"]=d["callEdges"][0]["targetStaticVA"]
        d["callEdges"][1]["targetLabels"]=d["callEdges"][0]["targetLabels"]
        with self.assertRaisesRegex(m.Gate,"Duplicate"):
            m.summarize(d)

    def test_direct_script_help_works_from_isolated_python(self):
        with tempfile.TemporaryDirectory() as dirname:
            proc=subprocess.run([sys.executable,"-I",str(Path(m.__file__).resolve()),
                                "--help"],cwd=dirname,capture_output=True,text=True,timeout=15)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertIn("--crosswalk",proc.stdout)

if __name__=="__main__":
    unittest.main()
