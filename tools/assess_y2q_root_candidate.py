#!/usr/bin/env python3
"""Offline CVE-2026-43499 eligibility triage for the exact HXL1 Galaxy S20+.

Read-only by default. This checks kernel source, recorded on-device identity,
configuration and optional original boot/kernel hashes. It produces a
research-only candidate artifact (JSON data, NOT an exploit binary).
Never writes to stock kernel trees, a phone, or Root-My-Galaxy support feeds.

Kernel-source heuristics do NOT prove exploitation, KASLR control, successful
credential transition, or KernelSU/DEFEX/KDP compatibility.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from prepare_samsung_vdso_compat import source_gate

FIRMWARE = "G986U1UESCHXL1"
MODEL = "SM-G986U1"
DEVICE = "y2q"
RELEASE = "4.19.113-27095354"
BUILD = "samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys"
CVE = "CVE-2026-43499"
SECURITY_CONFIG = (
    "CONFIG_UH_RKP", "CONFIG_KDP_CRED", "CONFIG_KDP_NS",
    "CONFIG_SECURITY_DEFEX", "CONFIG_RANDOMIZE_BASE",
    "CONFIG_MODULE_SIG_FORCE", "CONFIG_KPROBES", "CONFIG_FUTEX_PI",
)
SOURCE_FILES = ("kernel/locking/rtmutex.c", "kernel/futex.c")
BLOCKING_GATES = (
    "vendor_source_semantic_review",
    "device_runtime_reachability_test",
    "memory_safety_reproduction_in_isolated_lab",
    "samsung_el2_kdp_rkp_defex_effects_characterized",
    "complete_exploitation_chain_validated_on_owned_device",
    "loader_and_kernelsu_4_19_compatibility",
    "reboot_and_recovery_risk_review",
)


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as inp:
        for chunk in iter(lambda: inp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def strip_c_comments(text):
    """Preserve strings while removing common C comments for source triage."""
    pattern = re.compile(
        r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|(/\*[\s\S]*?\*/|//[^\n]*)'
    )
    return pattern.sub(lambda match: match.group(1) if match.group(1) is not None else
                       ("\n" * match.group(2).count("\n")), text)


def body_of_function(source, name):
    """Brace-aware extraction. Fail closed on ambiguous/missing function."""
    matches = list(re.finditer(
        r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", source
    ))
    if len(matches) != 1:
        return None
    opening = source.find("{", matches[0].start())
    depth = 0
    for i in range(opening, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:i]
    return None


def inspect_source(source_dir):
    base = source_dir.expanduser().resolve()
    if not base.is_dir():
        raise ValueError("stock source directory not found: " + str(base))
    paths = {}
    for relative in SOURCE_FILES:
        candidate = base / relative
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("missing/untrusted stock kernel file: " + str(candidate))
        paths[relative] = {
            "sha256": sha256(candidate), "bytes": candidate.stat().st_size,
        }
    mutex = strip_c_comments((base / SOURCE_FILES[0]).read_text(errors="replace"))
    futex = strip_c_comments((base / SOURCE_FILES[1]).read_text(errors="replace"))
    remove = body_of_function(mutex, "remove_waiter")
    proxy = body_of_function(mutex, "rt_mutex_start_proxy_lock")
    possible_current = bool(remove and re.search(r"\bcurrent\b", remove))
    waiter_task = bool(remove and re.search(r"\bwaiter\s*->\s*task\b", remove))
    signs = {
        "remove_waiterDefinitionFound": remove is not None,
        "usesCurrentInRemoveWaiter": possible_current,
        "usesWaiterTaskInRemoveWaiter": waiter_task,
        "proxyLockDefinitionFound": proxy is not None,
        "futexRequeueCallsProxyLock": bool(re.search(r"\brt_mutex_start_proxy_lock\s*\(", futex)),
    }
    if (remove is None or proxy is None
            or not signs["futexRequeueCallsProxyLock"]):
        category = "UNKNOWN_OR_VENDOR_DIFFERENT"
    elif possible_current and not waiter_task:
        category = "REVIEW_REQUIRED_POSSIBLE_UNFIXED_CODE_PATH"
    elif waiter_task and not possible_current:
        category = "REVIEW_REQUIRED_POSSIBLE_FIXED_CODE_PATH"
    else:
        category = "REVIEW_REQUIRED_AMBIGUOUS_CODE_PATH"
    return {
        "originalSamsungSource": str(base),
        "files": paths,
        "heuristic": signs,
        "classification": category,
        "interpretation": (
            "Heuristic inspection only. Vendor-specific modifications and "
            "inlined/backported fixes require manual code review; even a "
            "vulnerable function is not proof of a working exploit."
        ),
    }


def inspect_configuration(evidence):
    identity = evidence.get("identity", {})
    if (identity.get("model") != MODEL or identity.get("device") != DEVICE
            or identity.get("firmware") != FIRMWARE
            or identity.get("kernelRelease") != RELEASE
            or identity.get("fingerprint") != BUILD):
        raise ValueError("evidence identity mismatch: refuse cross-firmware target")
    if evidence.get("status") != "research-only":
        raise ValueError("evidence is not explicitly research-only")
    cfg = evidence.get("kernelConfig", {})
    props = {key: cfg.get(key, "unknown") for key in SECURITY_CONFIG}
    required = {"CONFIG_FUTEX_PI": "y", "CONFIG_RANDOMIZE_BASE": "y"}
    for name, value in required.items():
        if props[name] != value:
            raise ValueError("observed kernel configuration mismatch " + name)
    artifacts = evidence.get("artifacts", {})
    return {"verifiedIdentity": identity, "securityFeatures": props,
            "sourceArtifactHashes": {
                key: value.get("sha256") for key, value in artifacts.items()
                if isinstance(value, dict)
            }}


def inspect_boot_file(path, record, name):
    file = path.expanduser().resolve()
    if not file.is_file() or file.is_symlink():
        raise ValueError(name + " file not found or symlink: " + str(file))
    observed = sha256(file)
    if observed.lower() != record.lower():
        raise ValueError(name + " SHA-256 mismatch; do not mix firmware images")
    return {"file": str(file), "sha256": observed, "verified": True}


def make_report(evidence, source_report, image_checks):
    data = inspect_configuration(evidence)
    shizuku = evidence.get("shizuku", {})
    if shizuku.get("flashLocked") != "1" or shizuku.get("uid") != 2000:
        raise ValueError("on-device shell or flash lock mismatch")
    return {
        "schemaVersion": 1,
        "format": "root-my-galaxy-offline-research-candidate",
        "profileId": "y2q-G986U1UESCHXL1-candidate",
        "device": {"model": MODEL, "codename": DEVICE, "firmware": FIRMWARE,
                   "kernelRelease": RELEASE, "fingerprint": BUILD},
        "cve": CVE,
        "cveReference": "https://www.cve.org/CVERecord?id=CVE-2026-43499",
        "advisoryApplicability": (
            "Upstream 4.19 lies in published affected version range; "
            "Samsung backports and device exploitability unverified."
        ),
        "stockKernelInspection": source_report,
        "kernelConfig": data["securityFeatures"],
        "bootArtifactChecks": image_checks,
        "runtimeEvidence": {
            "shellUid": shizuku["uid"],
            "flashLocked": shizuku["flashLocked"],
            "selinux": shizuku.get("selinux"),
            "kallsymsAccessible": shizuku.get("procKallsymsAccessible"),
        },
        "referenceImplementations": [
            {"repo": "Ragnarok93/Root-My-Galaxy-Payloads",
             "purpose": "device profile and firmware research"},
            {"repo": "Ragnarok93/Root-My-Galaxy",
             "purpose": "application; support feed intentionally unchanged"},
            {"repo": "wxxsfxyzm/GhostLock-Galaxy",
             "purpose": "Shell/Shizuku-specific 6.1 reference, NOT portable"},
            {"repo": "YuKongA/ghostlock-app",
             "purpose": "exact uname-r profile validation patterns"},
            {"repo": "ccp-p/ghostlock-cve-2026-43499-4.19-k40",
             "purpose": "4.19 reference; no device-specific values reused"},
        ],
        "candidatePayload": {
            "kind": "metadata-only-non-executable",
            "executable": False,
            "rootGranted": False,
            "readyToInstall": False,
            "deviceTested": False,
            "kernelAddressOffsets": None,
            "privilegeEscalationPayload": None,
            "kernelSuArtifact": None,
            "allowRegistrationInSupportFeed": False,
            "deploymentBlocked": True,
        },
        "unmetGates": list(BLOCKING_GATES),
        "warnings": [
            "Never register as supported; version-only matching would be unsafe.",
            "No memory-corruption test, kernel write, credential edit or exploit executed.",
            "Kernel compilation is not required for this static triage.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--stock-source", type=Path, required=True)
    parser.add_argument("--audit-json", type=Path, required=True,
                        help="Original 11-layer Samsung source audit; must verify 40 overlay files")
    parser.add_argument("--boot-img", type=Path)
    parser.add_argument("--kernel-bin", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        evidence = json.loads(args.evidence.expanduser().read_text(encoding="utf-8"))
        data = inspect_configuration(evidence)
        verified_source = source_gate(args.stock_source.expanduser(), args.audit_json.expanduser())
        source_report = inspect_source(args.stock_source)
        source_report["sourceAudit"] = {
            "firmware": FIRMWARE,
            "originalKernelMakefile": verified_source["makefileVersion"]["matchesExpected"],
            "verifiedOverlayFiles": verified_source["overlayVerification"]["verified"],
            "deviceConfigHashesVerified": all(
                row["matchesOfficialAudit"]
                for row in verified_source["deviceConfigs"].values()
            ),
        }
        checks = {}
        for key, name, path in (("boot.img", "boot.img", args.boot_img),
                                ("kernel.bin", "kernel.bin", args.kernel_bin)):
            if path:
                digest = data["sourceArtifactHashes"].get(key)
                if not digest:
                    raise ValueError("no expected digest for " + name)
                checks[key] = inspect_boot_file(path, digest, name)
        report = make_report(evidence, source_report, checks)
        printable = json.dumps(report, indent=2) + "\n"
        if args.output:
            out = args.output.expanduser().absolute()
            if out.exists() or out.is_symlink():
                raise ValueError("refusing to overwrite report: " + str(out))
            if (args.stock_source.expanduser().resolve() in out.parents
                    or out.parent.is_symlink() or not out.parent.is_dir()):
                raise ValueError("output must be in existing ordinary directory outside stock source")
            with out.open("x", encoding="utf-8") as stream:
                stream.write(printable)
            print("Saved research-only candidate:", out)
        else:
            print(printable, end="")
        print("STATUS: RESEARCH ONLY; no executable root payload created.")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
