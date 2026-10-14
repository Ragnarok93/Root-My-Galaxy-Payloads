#!/usr/bin/env python3
"""Read-only HXL1 live device-tree root identity comparison.

Captures only public model/compatible and build/kernel strings over already
authorized ADB. Never reads serial identifiers, modifies the device, guesses
physical kernel addresses, or proves an exact bootloader-selected DTB.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

MODEL="SM-G986U1"
FIRMWARE="G986U1UESCHXL1"
KERNEL="4.19.113-27095354"
PROFILE="y2q-G986U1UESCHXL1-research"
EVIDENCE=Path(__file__).resolve().parents[1]/"research/y2q-G986U1UESCHXL1/evidence.json"
EVIDENCE_SHA="d12ac8a1f7f29e8d106f87cb439cb75d60aec4253c50d6b525c2cefdcdb49303"

class GateError(ValueError):
    pass


class DeviceTreeAccessError(GateError):
    """Non-root restriction or invalid remote cat result; not an FDT mismatch."""
    def __init__(self, build_identity, attempts, readable):
        super().__init__("Live device-tree root properties inaccessible")
        self.build_identity = build_identity
        self.attempts = attempts
        self.readable = readable


def require(ok, reason):
    if not ok:
        raise GateError(reason)

def candidate_models(evidence):
    require(evidence.get("identity",{}).get("model")==MODEL
            and evidence.get("identity",{}).get("firmware")==FIRMWARE,
            "Wrong original evidence identity")
    trees=(evidence.get("hxl1Stage4BootloaderDiscovery",{})
            .get("followupFdtStructureAndRootIdentity",{}).get("candidates",[]))
    require(len(trees)==4 and [x.get("index") for x in trees]==[1,2,3,4],
            "Invalid pinned stock FDT candidate inventory")
    require(all(t.get("tokenStatus")=="PASS" for t in trees),
            "Original FDT candidate structural status changed")
    require(all(isinstance(t.get("rootModel"),str) and t.get("rootCompatible")==["qcom,kona"]
                for t in trees[:3]) and trees[3].get("rootModel") is None,
            "Stock FDT root identities changed")
    return trees

def parse_root(data, allow_list=False, label="root property"):
    require(isinstance(data,bytes) and 0<len(data)<8192,
            label+": Missing/oversized device-tree root property")
    parts=data.split(b"\x00")
    parts=[p for p in parts if p]
    require(bool(parts), label+": Empty FDT root property")
    try:
        items=[p.decode("utf-8",errors="strict") for p in parts]
    except UnicodeDecodeError:
        raise GateError(label+": Non-UTF8 FDT root property")
    require(all(len(x)<1000 and x.isprintable() for x in items),
            label+": FDT root property contains unsafe/nonprintable bytes")
    if not allow_list:
        require(len(items)==1, label+": Ambiguous root model property")
        return items[0]
    return items


def property_diagnostic(raw):
    """Bounded, non-identifying raw-byte description; no silent normalization."""
    if not isinstance(raw, bytes):
        return {"typeError":"not bytes"}
    control=next((i for i,b in enumerate(raw)
                  if b != 0 and (b < 32 or b == 127)),None)
    return {
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
        "first128Hex":raw[:128].hex(),
        "last32Hex":raw[-32:].hex(),
        "nulTerminated":raw.endswith(b"\x00"),
        "nulSeparatedEntryCount":sum(bool(x) for x in raw.split(b"\x00")),
        "firstControlByteExcludingNul":(
            {"offset":control,"hex":f"{raw[control]:02x}"}
            if control is not None else None),
    }


def diagnose(evidence, raw_model, raw_compatible, properties):
    """Always retain a report for malformed live properties, never invent a match.

    The exact stock candidate list must validate before a parse failure is
    classified as a *device* property formatting issue.
    """
    candidate_models(evidence)
    try:
        accepted=analyze(evidence,raw_model,raw_compatible,properties)
    except GateError as err:
        return {
            "target":MODEL+"/"+FIRMWARE,
            "scope":"READ_ONLY_DEVICE_TREE_ROOT_MODEL_COMPARISON",
            "status":"ROOT_PROPERTY_PARSE_REQUIRES_REVIEW",
            "parseError":str(err),
            "rawPropertyDiagnostics":{
                "model":property_diagnostic(raw_model),
                "compatible":property_diagnostic(raw_compatible)},
            "candidateRootMatchUnambiguous":False,
            "matchingOriginalRootModelCandidateIndices":[],
            "candidateRootMatchProvesExactRuntimeDtb":False,
            "bootloaderSelectedDtbProven":False,
            "physicalLinuxLoadBaseVerified":False,
            "kernelRamOrKASLRMeasured":False,
            "deviceModified":False,
            "rootOrKernelSuDemonstrated":False,
            "limits":"Parsing failed: raw root property requires review. "
                     "Do not strip or reinterpret bytes, and do not certify "
                     "a runtime DTB match or Linux physical handoff.",
        }
    accepted["status"]="ROOT_PROPERTY_PARSED"
    return accepted

def analyze(evidence, raw_model, raw_compatible, properties):
    candidates=candidate_models(evidence)
    model=parse_root(raw_model,label="model")
    compatible=parse_root(raw_compatible,allow_list=True,label="compatible")
    device=properties.get("ro.product.model","").strip()
    build=properties.get("ro.build.display.id","").strip()
    kernel=properties.get("uname -r","").strip()
    identity_ok=(device==MODEL and FIRMWARE in build and kernel==KERNEL)
    matches=[x["index"] for x in candidates
             if x.get("rootModel")==model and
             all(v in compatible for v in x.get("rootCompatible",[]))
             and x.get("rootModel") is not None]
    return {
        "target":MODEL+"/"+FIRMWARE,
        "scope":"READ_ONLY_DEVICE_TREE_ROOT_MODEL_COMPARISON",
        "rawPropertiesSha256":{
            "model":hashlib.sha256(raw_model).hexdigest(),
            "compatible":hashlib.sha256(raw_compatible).hexdigest()},
        "observedRootModel":model,
        "observedRootCompatible":compatible,
        "observedBuildIdentity":{"model":device,"displayId":build,"kernelRelease":kernel},
        "liveIdentityMatchesPinnedHxl1":identity_ok,
        "matchingOriginalRootModelCandidateIndices":matches,
        "candidateRootMatchUnambiguous":identity_ok and len(matches)==1,
        "candidateRootMatchProvesExactRuntimeDtb":False,
        "bootloaderSelectedDtbProven":False,
        "physicalLinuxLoadBaseVerified":False,
        "kernelRamOrKASLRMeasured":False,
        "deviceModified":False,
        "rootOrKernelSuDemonstrated":False,
        "limits":"A root model/compatible match is metadata corroboration, not an "
                 "exact DTB byte match, proof of applied overlays, physical "
                 "Linux kernel handoff or authorization to load modules."}

def remote_cat_failure(raw):
    """ADB exec-out may exit 0 even though toybox cat printed its error."""
    if not isinstance(raw,bytes) or len(raw)>8192:
        return "UNAVAILABLE"
    normalized=raw.strip().lower()
    if not normalized.startswith(b"cat: ") or b"\x00" in raw:
        return None
    if normalized.endswith(b": permission denied"):
        return "PERMISSION_DENIED"
    if normalized.endswith(b": operation not permitted"):
        return "OPERATION_NOT_PERMITTED"
    if normalized.endswith(b": no such file or directory"):
        return "NOT_FOUND"
    if normalized.endswith(b": is a directory"):
        return "IS_DIRECTORY"
    return "REMOTE_CAT_ERROR"


def adb_read(adb, serial, args):
    cmd=[adb]+(["-s",serial] if serial else [])+args
    try:
        result=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,
                              timeout=15,check=False)
    except (OSError,subprocess.TimeoutExpired) as err:
        raise GateError("ADB_HOST_"+type(err).__name__.upper())
    require(len(result.stdout)<8192,"ADB_OUTPUT_EXCEEDED_LIMIT")
    if args[:2]==["exec-out","cat"]:
        code=remote_cat_failure(result.stdout)
        if code:
            raise GateError(code)
    require(result.returncode==0,"ADB_COMMAND_FAILED")
    return result.stdout


HINTS=("ro.hardware","ro.board.platform","ro.boot.hardware",
       "ro.boot.dtb_idx","ro.boot.dtbo_idx")


def capture_hints(adb, serial):
    """Optional public boot properties; neither IDs nor indices certify DTB."""
    hints={}
    for key in HINTS:
        try:
            value=adb_read(adb,serial,["shell","getprop",key])
            text=value.decode("utf-8","strict").strip()
            hints[key]=text if len(text)<128 and text.isprintable() else ""
        except (GateError,UnicodeDecodeError):
            hints[key]=""
    return hints


def access_report(err, hints):
    require(isinstance(err,DeviceTreeAccessError),
            "Expected explicit permission/access exception")
    return {
        "target":MODEL+"/"+FIRMWARE,
        "scope":"READ_ONLY_DEVICE_TREE_ROOT_MODEL_COMPARISON",
        "status":"ROOT_PROPERTIES_INACCESSIBLE",
        "rootReadAttempts":err.attempts,
        "readableRawRootProperties":err.readable,
        "observedBuildIdentity":err.build_identity,
        "liveIdentityMatchesPinnedHxl1":(
            err.build_identity.get("ro.product.model")==MODEL and
            FIRMWARE in err.build_identity.get("ro.build.display.id","") and
            err.build_identity.get("uname -r")==KERNEL),
        "readOnlyBootPropertyHints":hints,
        "bootPropertyHintsProveSelectedDtb":False,
        "matchingOriginalRootModelCandidateIndices":[],
        "candidateRootMatchUnambiguous":False,
        "candidateRootMatchProvesExactRuntimeDtb":False,
        "bootloaderSelectedDtbProven":False,
        "physicalLinuxLoadBaseVerified":False,
        "kernelRamOrKASLRMeasured":False,
        "deviceModified":False,
        "rootOrKernelSuDemonstrated":False,
        "limits":"ADB cat diagnostic text is not DTB data. The root properties "
                 "are inaccessible or unreadable to the shell UID. "
                 "Allowlisted Android boot properties are only unverified "
                 "hints and cannot prove original DTB selection, overlay "
                 "state, kernel physical handoff, or KASLR."
    }


def capture(adb, serial):
    props={}
    for key in ("ro.product.model","ro.build.display.id"):
        props[key]=adb_read(adb,serial,["shell","getprop",key]).decode("utf-8","replace").strip()
    props["uname -r"]=adb_read(adb,serial,["shell","uname","-r"]).decode("utf-8","replace").strip()
    attempts=[]
    def tree(name):
        for root in ("/sys/firmware/devicetree/base","/proc/device-tree"):
            try:
                value=adb_read(adb,serial,["exec-out","cat",root+"/"+name])
                if value and value.endswith(b"\x00"):
                    attempts.append({"property":name,"source":root,
                                     "status":"READ_OK_NUL_TERMINATED"})
                    return value
                attempts.append({"property":name,"source":root,
                                 "status":"NOT_NUL_TERMINATED_OR_EMPTY"})
            except GateError as exc:
                attempts.append({"property":name,"source":root,
                                 "status":str(exc)})
        return None
    model,compatible=tree("model"),tree("compatible")
    if model is None or compatible is None:
        raise DeviceTreeAccessError(props,attempts,
                                    {"model":model is not None,
                                     "compatible":compatible is not None})
    return model,compatible,props


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--adb",default="adb")
    p.add_argument("--adb-serial",default=None,help="Optional ADB transport selector (never saved)")
    p.add_argument("--output",required=True,type=Path,help="New JSON file outside repository")
    p.add_argument("--evidence",type=Path,default=EVIDENCE)
    args=p.parse_args()
    try:
        raw=args.evidence.read_bytes()
        require(hashlib.sha256(raw).hexdigest()==EVIDENCE_SHA,
                "Exact original research manifest SHA-256 mismatch")
        evidence=json.loads(raw)
        dest=args.output.expanduser().resolve()
        repository=Path(__file__).resolve().parents[1]
        require(repository not in dest.parents and dest!=repository,
                "Output cannot be written inside repository")
        require(not dest.exists() and not dest.is_symlink(),
                "Refusing to overwrite existing evidence")
        try:
            model,compatible,props=capture(args.adb,args.adb_serial)
            result=diagnose(evidence,model,compatible,props)
        except DeviceTreeAccessError as exc:
            result=access_report(exc,capture_hints(args.adb,args.adb_serial))
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        if result["status"]!="ROOT_PROPERTY_PARSED":
            print("[STOP]",result.get("parseError",result["status"]),file=sys.stderr)
            print("[DIAGNOSTIC REPORT]",dest)
            return 2
        print("[HXL1 LIVE IDENTITY MATCH]",result["liveIdentityMatchesPinnedHxl1"])
        print("[ORIGINAL MODEL CANDIDATES]",result["matchingOriginalRootModelCandidateIndices"])
        print("[PHYSICAL HANDOFF/BOOTLOADER DTB SELECTED]", "NOT VERIFIED")
        print("[REPORT]",dest)
        return 0
    except (OSError,ValueError,TypeError) as e:
        print("[STOP]",e,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
