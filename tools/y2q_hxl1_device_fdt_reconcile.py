#!/usr/bin/env python3
"""Read-only HXL1 runtime device-tree vs SHA-pinned stock firmware comparison.

Consumes the *existing* ADB identity.json; never invokes ADB or edits the
device. Reuses the canonical original boot.img/FDT hash-and-token audit.
A matching runtime root identity DOES NOT prove physical bootloader selection,
an identical runtime DTB, kernel load addresses, root or KernelSU.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import y2q_stock_fdt_semantic_audit as stock

ROOT = Path.home() / "s20-artifacts"
REPO = Path(__file__).resolve().parents[1]
TARGET = "SM-G986U1"
BUILD = "G986U1UESCHXL1"
MAX_JSON = 2 * 1024 * 1024


class ReconcileError(ValueError):
    pass


def demand(condition: bool, reason: str) -> None:
    if not condition:
        raise ReconcileError(reason)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for part in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def read_json(path: Path) -> dict:
    demand(path.is_file() and not path.is_symlink() and
           0 < path.stat().st_size <= MAX_JSON,
           "Missing, unsafe, or oversized JSON: " + str(path))
    value = json.loads(path.read_text(encoding="utf-8"))
    demand(isinstance(value, dict), "JSON must contain an object")
    return value


def read_snapshot(path: Path) -> dict:
    data = read_json(path)
    demand(data.get("schemaVersion") == 1
           and data.get("target") == TARGET
           and data.get("firmware") == BUILD
           and data.get("scope") == "READ_ONLY_UNPRIVILEGED_DEVICE_IDENTITY",
           "Unexpected device snapshot identity/schema")
    demand(isinstance(data.get("properties"), dict)
           and isinstance(data.get("deviceReads"), dict),
           "Missing original device values")
    demand(data.get("stage4Complete") is False
           and data.get("stage5Complete") is False
           and data.get("rootVerified") is False,
           "Saved device snapshot unexpectedly claims completed privileges")
    return data


def read_manifest(path: Path) -> dict:
    data = read_json(path)
    identity = data.get("identity")
    demand(isinstance(identity, dict)
           and identity.get("model") == TARGET
           and identity.get("firmware") == BUILD
           and identity.get("device") == "y2q",
           "Unexpected original research manifest")
    artifacts = data.get("artifacts")
    demand(isinstance(artifacts, dict)
           and artifacts.get("boot.img", {}).get("sha256") == stock.PINS["boot.img"]
           and artifacts.get("dtb.img", {}).get("sha256") == stock.PINS["dtb.img"],
           "Original firmware manifest hash differs from pinned parser")
    return data


def runtime_value(snapshot: dict, key: str) -> str | list[str] | None:
    item = snapshot["deviceReads"].get(key)
    if not isinstance(item, dict) or item.get("state") != "READ":
        return None
    return item.get("value")


def check_runtime_identity(snapshot: dict, manifest: dict) -> dict:
    props = snapshot["properties"]
    identity = manifest["identity"]
    release = runtime_value(snapshot, "kernelRelease")
    checks = {
        "model": props.get("ro.product.model") == identity["model"],
        "device": props.get("ro.product.device") == identity["device"],
        "fingerprint": props.get("ro.build.fingerprint") == identity["fingerprint"],
        "displayBuild": props.get("ro.build.display.id") == identity["displayBuild"],
        "bootloader": props.get("ro.bootloader") == BUILD,
        "kernelRelease": release == identity["kernelRelease"],
        "kernelArchitecture": runtime_value(snapshot, "kernelArchitecture") in
                              ("aarch64", "arm64"),
    }
    original = snapshot.get("checks", {})
    demand(isinstance(original, dict)
           and original.get("identityConsistentWithTarget") is True,
           "Supplied snapshot did not pass its own target identity check")
    return {"checks": checks,
            "strictManifestIdentityMatches": all(checks.values()),
            "runtimeDataOrigin": "ORIGINAL_READ_ONLY_ADB_SNAPSHOT",
            "originalRunningImageByteEquivalentToFirmware": False}


def classify_boot_state(properties: dict) -> dict:
    flash = properties.get("ro.boot.flash.locked", "")
    vbmeta = properties.get("ro.boot.vbmeta.device_state", "")
    verified = properties.get("ro.boot.verifiedbootstate", "")
    if flash == "1" and vbmeta == "locked":
        classification = "REPORTED_LOCKED"
    elif flash == "0" and vbmeta == "unlocked":
        classification = "REPORTED_UNLOCKED"
    elif flash or vbmeta:
        classification = "UNKNOWN_OR_CONTRADICTORY"
    else:
        classification = "UNREPORTED"
    return {"classification": classification,
            "flashLockedReported": flash,
            "vbmetaDeviceStateReported": vbmeta,
            "verifiedBootStateReported": verified,
            "bootloaderHardwareFuseStateVerified": False,
            "customImageFlashabilityVerified": False}


def compare_dtb(snapshot: dict, firmware: dict) -> dict:
    model = runtime_value(snapshot, "dtModel")
    compatible = runtime_value(snapshot, "dtCompatible")
    demand(model is None or isinstance(model, str),
           "Runtime DT model must be string or unavailable")
    demand(compatible is None or
           (isinstance(compatible, list) and
            all(isinstance(part, str) for part in compatible)),
           "Runtime DT compatible must be string list or unavailable")
    candidates = firmware.get("candidates", [])
    demand(firmware.get("allFdtStructuresPass") is True
           and firmware.get("contiguousCompleteRegionCoverage") is True
           and firmware.get("originalFirmwareBootAndDtbSha256Verified") is True
           and len(candidates) == 4,
           "Original pinned HXL1 FDT candidate audit incomplete")
    examined = []
    for item in candidates:
        demand(item.get("fullStructureTokenValidation") == "PASS",
               "Unexpected invalid original FDT candidate")
        original_models = item.get("rootModel", [])
        original_compat = item.get("rootCompatible", [])
        demand(isinstance(original_models, list) and
               isinstance(original_compat, list),
               "Malformed original FDT identifiers")
        exact_model = bool(model and model in original_models)
        common = sorted(set(compatible or []).intersection(original_compat))
        examined.append({
            "candidateIndex": item["index"],
            "originalDtbSha256": item["sha256"],
            "originalRootModel": original_models,
            "originalRootCompatible": original_compat,
            "runtimeModelMatches": exact_model,
            "sharedCompatibleStrings": common,
            "rootIdentityMatchClass":
                "MODEL_AND_COMPATIBLE" if exact_model and common else
                "MODEL_ONLY" if exact_model else
                "COMPATIBLE_ONLY" if common else "NO_MATCH",
            "exactDeviceTreeBinarySelectedProven": False,
        })
    exact = [i["candidateIndex"] for i in examined
             if i["rootIdentityMatchClass"] == "MODEL_AND_COMPATIBLE"]
    models = [i["candidateIndex"] for i in examined
              if i["runtimeModelMatches"]]
    compatibles = [i["candidateIndex"] for i in examined
                   if i["sharedCompatibleStrings"]]
    if model is None and compatible is None:
        state = "RUNTIME_PROPERTIES_UNAVAILABLE"
    elif not model and not compatible:
        state = "RUNTIME_PROPERTIES_EMPTY_OR_PARTIALLY_UNAVAILABLE"
    elif len(exact) == 1:
        state = "ONE_MODEL_AND_COMPATIBLE_IDENTITY_MATCH"
    elif len(exact) > 1:
        state = "AMBIGUOUS_MODEL_AND_COMPATIBLE_MATCHES"
    elif models:
        state = "MODEL_MATCH_ONLY"
    elif compatibles:
        state = "COMPATIBLE_MATCH_ONLY"
    else:
        state = "NO_ROOT_IDENTITY_MATCH"
    return {"runtimeRootModel": model,
            "runtimeRootCompatible": compatible,
            "runtimeModelReadState": snapshot["deviceReads"].get("dtModel", {}).get("state", "MISSING"),
            "runtimeCompatibleReadState": snapshot["deviceReads"].get("dtCompatible", {}).get("state", "MISSING"),
            "runtimeRootModelPresent": bool(model),
            "runtimeRootCompatiblePresent": bool(compatible),
            "classification": state,
            "modelAndCompatibleMatches": exact,
            "modelMatches": models,
            "compatibleMatches": compatibles,
            "candidates": examined,
            "inferenceLimit": "Root property agreement does not establish identical "
                              "full DTB bytes or bootloader-selected original DTB; "
                              "overlays can modify the device tree.",
            "selectedPhysicalDtbVerified": False,
            "kernelPhysicalHandoffVerified": False}


def reconcile(snapshot_path: Path, artifacts: Path, manifest_path: Path) -> dict:
    snapshot = read_snapshot(snapshot_path)
    manifest = read_manifest(manifest_path)
    firmware = stock.audit(artifacts)
    return {
        "schemaVersion": 1, "target": TARGET, "firmware": BUILD,
        "scope": "READ_ONLY_STOCK_FDT_VS_SAVED_DEVICE_IDENTITY",
        "inputSnapshotSha256": sha256(snapshot_path),
        "referenceManifestSha256": sha256(manifest_path),
        "originalFirmwareHashesRechecked": True,
        "originalEmbeddedFdtCount": firmware["fdtHeaderCandidates"],
        "deviceIdentity": check_runtime_identity(snapshot, manifest),
        "bootState": classify_boot_state(snapshot["properties"]),
        "deviceTree": compare_dtb(snapshot, firmware),
        "stage4Complete": False, "stage5Complete": False,
        "factoryKernelMemoryLayoutProven": False,
        "rootVerified": False, "kernelSuLoaded": False, "deviceModified": False,
    }


def markdown(report: dict) -> str:
    identity = report["deviceIdentity"]
    tree = report["deviceTree"]
    lock = report["bootState"]
    rows = [
        "# HXL1 runtime vs original stock DTB root identities",
        "",
        "**Read-only comparison. Bootloader handoff and root remain unverified.**",
        "",
        "- Strict firmware identity: " +
            ("MATCH" if identity["strictManifestIdentityMatches"] else "MISMATCH"),
        "- Boot state: " + lock["classification"],
        "- DT comparison: " + tree["classification"],
        "- Runtime DT model read: " + tree["runtimeModelReadState"],
        "- Runtime DT compatible read: " + tree["runtimeCompatibleReadState"],
        "- Runtime root model: " + repr(tree["runtimeRootModel"]),
        "- Runtime compatible strings: " + repr(tree["runtimeRootCompatible"]),
        "- Embedded original DTBs checked: " + str(report["originalEmbeddedFdtCount"]),
        "",
        "| Candidate | Root model | Root compatible | Runtime relation |",
        "| ---: | --- | --- | --- |",
    ]
    for row in tree["candidates"]:
        rows.append("| {} | {} | {} | {} |".format(
            row["candidateIndex"],
            ", ".join(row["originalRootModel"]) or "(unavailable)",
            ", ".join(row["originalRootCompatible"]) or "(unavailable)",
            row["rootIdentityMatchClass"]))
    rows += [
        "",
        "These are root-property comparisons, not original DTB selection proofs.",
        "The running tree may have bootloader overlays or edits.",
        "Neither this snapshot nor matching firmware ID proves physical Linux "
        "load addresses, GhostLock runtime feasibility, or KernelSU.",
        "",
        "## Strict identity fields",
        "",
    ]
    for name, matched in identity["checks"].items():
        rows.append("- " + name + ": " + ("MATCH" if matched else "MISMATCH"))
    rows.append("")
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=ROOT)
    parser.add_argument("--snapshot", type=Path,
                        help="Existing HXL1 identity.json (defaults to newest)")
    parser.add_argument("--manifest", type=Path,
                        default=REPO / "research/y2q-G986U1UESCHXL1/evidence.json")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    artifacts = args.artifacts.expanduser().absolute()
    manifest = args.manifest.expanduser().absolute()
    if args.snapshot is None:
        snapshots = sorted((artifacts / "hxl1-research").glob(
            "device-identity-*/identity.json"))
        snapshot = snapshots[-1] if snapshots else None
    else:
        snapshot = args.snapshot.expanduser().absolute()
    try:
        demand(snapshot is not None, "No previous identity.json snapshot; "
               "run the existing read-only HXL1 device identity collector")
        output = (args.output_dir or artifacts / "hxl1-research" /
                  ("device-fdt-comparison-" +
                   datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")))
        output = output.expanduser().absolute()
        demand(not output.exists() and not output.is_symlink(),
               "New report directory required; never overwrite original evidence")
        for protected in (snapshot, manifest, artifacts / "boot.img"):
            demand(output != protected and protected not in output.parents,
                   "Output must not overlap original evidence")
        result = reconcile(snapshot, artifacts, manifest)
        output.mkdir(parents=True, exist_ok=False)
        (output / "device-fdt-comparison.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8")
        (output / "device-fdt-comparison.md").write_text(
            markdown(result), encoding="utf-8")
        print("[STRICT DEVICE IDENTITY]",
              "MATCH" if result["deviceIdentity"]["strictManifestIdentityMatches"]
              else "MISMATCH")
        print("[BOOT STATE]", result["bootState"]["classification"])
        print("[RUNTIME DT ROOT IDENTITY]", result["deviceTree"]["classification"])
        print("[RUNTIME DT MODEL]", repr(result["deviceTree"]["runtimeRootModel"]))
        print("[RUNTIME DT COMPATIBLE]", repr(result["deviceTree"]["runtimeRootCompatible"]))
        print("[DT READ STATES]",
              result["deviceTree"]["runtimeModelReadState"],
              result["deviceTree"]["runtimeCompatibleReadState"])
        print("[PHYSICAL BOOTLOADER HANDOFF VERIFIED] NO")
        print("[ROOT VERIFIED] NO")
        print("[REPORT]", output / "device-fdt-comparison.md")
        return 0 if result["deviceIdentity"]["strictManifestIdentityMatches"] else 3
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("[STOP]", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
