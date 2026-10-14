#!/usr/bin/env python3
"""Categorize 21 stock HXL1 sendmsg branch labels, preserving trampoline uncertainty.

Consumes the already completed 41-call original-Image/NM crosswalk. This
does not analyze live addresses, produce a GhostLock payload, infer C locals,
establish register targets, or validate runtime or KernelSU behavior.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

REPO=Path(__file__).resolve().parents[1]
EXPECTED_NM="c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f"
EXPECTED_KERNEL="ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123"
LABEL_COUNTS={
    "__stack_chk_fail":5,"__kmalloc":1,"kfree":1,
    "__check_object_size":2,"fput":4,"__fdget":3,
    "security_socket_sendmsg":2,"import_iovec":1,"import_single_range":1,
    "move_addr_to_kernel":2,"___sys_sendmsg":3,
    "copy_msghdr_from_user":1,"sock_kmalloc":1,"sock_kfree_s":1,
    "get_compat_msghdr":1,"cmsghdr_from_user_compat_to_kern":1,
    "__arch_copy_from_user":3,"__pi_memcmp":1,
    "__memcpy|__pi_memcpy":1,"__memset|__pi_memset":3,
    "jopp_springboard_blr_x8":3,
}
BUCKETS={
    "stack_protector_failure":{"__stack_chk_fail"},
    "allocator_or_free":{"__kmalloc","kfree","sock_kmalloc","sock_kfree_s"},
    "security_check":{"security_socket_sendmsg"},
    "jop_trampoline":{"jopp_springboard_blr_x8"},
    "sendmsg_internal":{"___sys_sendmsg","copy_msghdr_from_user"},
    "fd_lookup_release":{"fput","__fdget"},
    "iovec_and_address_copy":{"import_iovec","import_single_range",
                              "move_addr_to_kernel","__check_object_size",
                              "__arch_copy_from_user"},
    "compat_conversion":{"get_compat_msghdr",
                         "cmsghdr_from_user_compat_to_kern"},
    "memory_primitive":{"__pi_memcmp","__memcpy|__pi_memcpy",
                        "__memset|__pi_memset"},
}
EXPECTED_CALLER_COUNTS={
    "__sys_sendmsg":4,"___sys_sendmsg":15,"__sys_sendto":7,
    "__sys_sendmmsg":6,"rw_copy_check_uvector":4,"copy_msghdr_from_user":5,
}
REQUIRED_EDGES={
    ("__sys_sendmsg","0xffffff800966f248","___sys_sendmsg"),
    ("__sys_sendmmsg","0xffffff800966f750","___sys_sendmsg"),
    ("__sys_sendmmsg","0xffffff800966f7d4","___sys_sendmsg"),
    ("___sys_sendmsg","0xffffff800966f304","copy_msghdr_from_user"),
}
class Gate(ValueError):
    pass

def need(ok,what):
    if not ok: raise Gate(what)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def labelkey(labels):
    need(isinstance(labels,list) and labels and
         len(labels)==len(set(labels)) and
         all(isinstance(v,str) and v for v in labels),
         "Invalid or duplicate recovered label aliases")
    return "|".join(sorted(labels))

def summarize(d):
    need(isinstance(d,dict) and d.get("schemaVersion")==1 and
         d.get("target")=="SM-G986U1/G986U1UESCHXL1" and
         d.get("scope")=="STATIC_ORIGINAL_SENDMSG_CALLS_TO_RECOVERED_NM_LABELS_ONLY" and
         d.get("nmSha256")==EXPECTED_NM and
         d.get("stockImageSha256ReportedByEarlierAttestor")==EXPECTED_KERNEL and
         d.get("callsites")==41 and d.get("uniqueDestinations")==21 and
         d.get("exactSymbolDestinations")==21 and
         d.get("uncertainInteriorDestinations")==0,
         "Unexpected original crosswalk provenance/counts")
    for field in ("calleeSourceFunctionIdentityVerified",
                  "callArgumentPointerDataflowVerified",
                  "sendmsgFutexWaiterLifetimeOverlapVerified",
                  "originalKernelPhysicalLoadBaseVerified",
                  "liveGhostLockExploitVerified",
                  "rootOrKernelSuVerified","deviceModified"):
        need(d.get(field) is False,"Unsubstantiated upstream success flag: "+field)
    targets=d.get("directTargets")
    edges=d.get("callEdges")
    need(isinstance(targets,list) and len(targets)==21 and
         isinstance(edges,list) and len(edges)==41,
         "Missing exact original target/edge inventory")
    mapping={}
    claimed={}
    for entry in targets:
        need(isinstance(entry,dict) and
             entry.get("status")=="EXACT_RECOVERED_TEXT_LABEL" and
             entry.get("calleeCompilerFunctionIdentityVerified") is False,
             "Original recovered label treated as authenticated compiler function")
        address=entry.get("targetStaticVA")
        need(isinstance(address,str) and address.startswith("0x") and
             address not in mapping and int(address,16)%4==0,
             "Duplicate/unaligned original branch target")
        key=labelkey(entry.get("labels"))
        mapping[address]=key
        claimed[address]=entry.get("totalIncomingCalls")
    observed=Counter()
    callers=Counter()
    keyed_edges=set()
    bucket_counts=Counter()
    trampoline_sites=[]
    for edge in edges:
        need(isinstance(edge,dict) and
             edge.get("targetLabelMatch")=="EXACT_RECOVERED_TEXT_LABEL" and
             edge.get("registerArgumentsTraced") is False,
             "Invalid original edge/argument proof")
        caller,site,target=(edge.get("caller"),edge.get("callStaticVA"),
                            edge.get("targetStaticVA"))
        need(caller in EXPECTED_CALLER_COUNTS and
             isinstance(site,str) and site.startswith("0x") and
             int(site,16)%4==0 and target in mapping and
             labelkey(edge.get("targetLabels"))==mapping[target],
             "Original callsite/target binding mismatch")
        k=(caller,site,target)
        need(k not in keyed_edges,"Duplicate original callsite")
        keyed_edges.add(k)
        observed[target]+=1
        callers[caller]+=1
        label=mapping[target]
        bucket=next((b for b,names in BUCKETS.items() if label in names),None)
        need(bucket is not None,"Unclassified original branch label")
        bucket_counts[bucket]+=1
        if bucket=="jop_trampoline":
            trampoline_sites.append({"caller":caller,
                                     "callStaticVA":site,
                                     "immediateBranchDestination":target,
                                     "trampolineLabel":label,
                                     "effectiveCalleeIdentified":False,
                                     "x8RegisterTargetProven":False})
    counts=Counter(mapping[target] for target in mapping)
    need(all(v==1 for v in counts.values()) and set(counts)==set(LABEL_COUNTS),
         "Original 21-label inventory drift")
    frequencies=Counter()
    for addr,label in mapping.items():
        need(observed[addr]==claimed[addr] and
             observed[addr]==LABEL_COUNTS[label],
             "Original label/call count drift: "+label)
        frequencies[label]+=observed[addr]
    need(dict(callers)==EXPECTED_CALLER_COUNTS and
         len(keyed_edges)==41 and len(trampoline_sites)==3,
         "Original caller/JOP-trampoline inventory drift")
    found={(x["caller"],x["callStaticVA"],mapping[x["targetStaticVA"]])
           for x in edges}
    need(REQUIRED_EDGES.issubset(found),"Authenticated internal call edges lost")
    need(sum(bucket_counts.values())==41 and
         set(BUCKETS.keys())==set(bucket_counts),
         "Bucket coverage does not account for every original call")
    return {
      "schemaVersion":1,"target":d["target"],
      "scope":"HXL1_STATIC_CALLSITE_HELPER_CLASSES_WITH_JOP_TRAMPOLINE_CAVEAT",
      "originalRecoveredNmSha256":EXPECTED_NM,
      "originalKernelImageSha256ReportedByEarlierAttestor":EXPECTED_KERNEL,
      "staticCallsites":41,"distinctImmediateBranchDestinations":21,
      "exactRecoveredDestinationLabels":21,
      "staticCallsitesByCaller":dict(sorted(callers.items())),
      "staticCallsitesByHelperClass":dict(sorted(bucket_counts.items())),
      "staticCallsitesByRecoveredLabel":dict(sorted(frequencies.items())),
      "branchToNamedJopTrampolineCount":len(trampoline_sites),
      "jopTrampolineSites":sorted(trampoline_sites,key=lambda v:v["callStaticVA"]),
      "effectiveCalleeResolvedForJopTrampoline":False,
      "effectiveCallTargetCountMayExceedStaticDestinationCount":True,
      "stackProtectorFailureBranchSites":bucket_counts["stack_protector_failure"],
      "runtimeExecutionFrequencyMeasured":False,
      "mallocFreeObjectPairingProven":False,
      "sendmsgBufferCSourceIdentityVerified":False,
      "futexWaiterSendmsgStackAliasVerified":False,
      "ghostLockRootVerified":False,
      "kernelSuLoaded":False,
      "deviceModified":False,
      "limits":"A recovered label identifies the direct branch destination. "
               "Samsung JOP springboard names are not proof of the eventual "
               "callee or an x8 value. Calls to allocation/free helpers do not "
               "establish object pairing, pointer escape, or stack reuse."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--crosswalk",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    try:
        src=a.crosswalk.expanduser().absolute()
        out=a.output.expanduser().resolve()
        need(src.is_file() and not src.is_symlink() and
             0<src.stat().st_size<300000,"Missing/oversized original crosswalk")
        need(not a.output.expanduser().is_symlink() and
             not out.exists() and out!=REPO and REPO not in out.parents,
             "Refusing source-tree or previous-evidence output")
        raw=src.read_bytes()
        report=summarize(json.loads(raw))
        report["ownerCrosswalkJsonSha256"]=digest(raw)
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("x",encoding="utf-8") as file:
            json.dump(report,file,indent=2)
            file.write("\n")
        print("[EXACT STATIC LABELS] 21 / 21")
        print("[NAMED JOP SPRINGBOARD CALLS]",report["branchToNamedJopTrampolineCount"])
        print("[EFFECTIVE TRAMPOLINE CALLEE / WAITER ALIAS / ROOT] UNVERIFIED")
        print("[REPORT]",out)
        return 0
    except (OSError,UnicodeError,ValueError,KeyError,TypeError) as error:
        print("[STOP]",error,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
