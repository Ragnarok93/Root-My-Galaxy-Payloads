#!/usr/bin/env python3
"""Root My Galaxy SM-G986U1 HXL1: read-only nine-stage port readiness report.

Mirrors docs/PORTING.md, without mixing firmware/ELF provenance with a
working root exploit or KernelSU loader. No ADB, kernel compilation, patches,
module loading, phone writes, or support-feed publication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

FIRMWARE = "G986U1UESCHXL1"
PROFILE = "y2q-G986U1UESCHXL1"
MODEL = "SM-G986U1"
KERNEL = "4.19.113-27095354"
STOCK_HASHES = {
    "kernel/locking/rtmutex.c":
        "36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9",
    "kernel/futex.c":
        "493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5",
}
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACTS = Path.home() / "s20-artifacts"
DEFAULT_SOURCE = Path.home() / "src/samsung-y2q-hxl1-stock"
EVIDENCE = ROOT / "research/y2q-G986U1UESCHXL1/evidence.json"


class GateError(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def validate_evidence(data: dict) -> None:
    identity = data.get("identity", {})
    actual = (identity.get("model"), identity.get("firmware"),
              identity.get("kernelRelease"))
    if actual != (MODEL, FIRMWARE, KERNEL):
        raise GateError(f"STOP: evidence identity mismatch: {actual}")
    if data.get("profileId") != PROFILE + "-research":
        raise GateError("STOP: not the verified research profile")


def artifacts_check(data: dict, folder: Path) -> dict:
    checked = {}
    for name in ("boot.img", "kernel.bin", "config.gz"):
        item = data.get("artifacts", {}).get(name, {})
        target = folder / name
        expected = item.get("sha256", "")
        if not re.fullmatch("[0-9a-f]{64}", expected):
            raise GateError(f"Invalid expected SHA-256 for {name}")
        if target.is_file():
            actual = sha256(target)
            if actual != expected:
                raise GateError(
                    f"STOP: {name} differs from pinned firmware SHA-256")
            if target.stat().st_size != item.get("sizeBytes"):
                raise GateError(f"STOP: size mismatch for {name}")
            checked[name] = {"state": "MATCH", "sha256": actual}
        else:
            checked[name] = {"state": "NOT_AVAILABLE_LOCALLY",
                             "expectedSha256": expected}
    return checked


def source_check(vendor: Path) -> dict:
    state = {}
    for rel, expected in STOCK_HASHES.items():
        file = vendor / rel
        if not file.is_file():
            state[rel] = {"state": "NOT_AVAILABLE_LOCALLY"}
            continue
        value = sha256(file)
        if value != expected:
            raise GateError(f"STOP: Samsung source hash mismatch: {rel}")
        state[rel] = {"state": "MATCH", "sha256": value}
    return state


def btf_candidates(kernel: Path) -> dict:
    """Identify *full-header-valid* standalone BTF records in original Image.

    A negative scan says only that no uncompressed raw BTF header was located.
    It does not prove the original build had no BTF in other artifacts.
    """
    if not kernel.is_file():
        return {"status": "NOT_AVAILABLE_LOCALLY", "candidates": []}
    data = kernel.read_bytes()
    matches = []
    cursor = 0
    magic = b"\x9f\xeb\x01\x00"
    while True:
        offset = data.find(magic, cursor)
        if offset == -1:
            break
        cursor = offset + 1
        if offset + 24 > len(data):
            continue
        unpacked = struct.unpack_from("<HBBIIIII", data, offset)
        m, version, flags, hdr, typeoff, typelen, stroff, strlen = unpacked
        if (m != 0xEB9F or version != 1 or flags != 0 or hdr < 24
                or hdr > 256 or typelen == 0 or strlen == 0):
            continue
        payload = offset + hdr
        type_start, type_end = payload + typeoff, payload + typeoff + typelen
        str_start, str_end = payload + stroff, payload + stroff + strlen
        if (type_start >= type_end or type_end > len(data)
                or str_start >= str_end or str_end > len(data)
                or data[str_start] != 0):
            continue
        matches.append({"fileOffset": hex(offset), "endOffset":
                        hex(max(type_end, str_end)), "bytes":
                        max(type_end, str_end) - offset})
    return {
        "status": ("ONE_RAW_BTF_CANDIDATE" if len(matches) == 1
                   else "NO_RAW_BTF_CANDIDATE" if not matches
                   else "AMBIGUOUS_RAW_BTF_CANDIDATES"),
        "candidates": matches,
        "scope": "original extracted kernel.bin, raw uncompressed BTF only",
    }


def stage4_factory_evidence(evidence: dict) -> dict:
    """Summarize owner-attested factory firmware audits without claiming live handoff.

    This is evidence MANIFEST provenance; a hash recorded in the manifest
    is not equivalent to checking the original BL tar.md5 again locally.
    """
    s = evidence.get("hxl1Stage4BootloaderDiscovery", {})
    archive = s.get("archive", {})
    bl = s.get("ownerBootloaderElfAuditVerified", {})
    boot = s.get("followupBootImageV2Audit", {})
    fdt = s.get("followupFdtStructureAndRootIdentity", {})
    bl_verified = (
        archive.get("sha256") ==
        "f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b"
        and archive.get("fileEntriesCount") == 27
        and bl.get("regression", {}).get("passed") == 10
        and bl.get("artifactIntegrity", "").startswith("[PASS]"))
    boot_verified = (
        boot.get("regression", {}).get("passed") == 13
        and boot.get("bootImageIntegrity") == "PRESENT_PIN_VERIFIED"
        and all(
            boot.get("embeddedComponents", {}).get(name, {}).get("checksumPinMatch") is True
            for name in ("kernel", "ramdisk", "dtb")))
    fdt_verified = (
        fdt.get("regression", {}).get("passed") == 10
        and fdt.get("bootAndEmbeddedDtbSha256Verified") is True
        and fdt.get("contiguousCompleteRegionCoverage") is True
        and fdt.get("allFdtStructuresPass") is True
        and len(fdt.get("candidates", [])) == 4
        and all(x.get("tokenStatus") == "PASS"
                for x in fdt.get("candidates", [])))
    return {
        "ownerManifestVerifiesExactHxl1BL": bl_verified,
        "ownerManifestVerifiesBootV2AndEmbeddedPayloads": boot_verified,
        "ownerManifestVerifiesFourFdtTokenStreams": fdt_verified,
        "actualKernelPhysicalLoadVerified": False,
        "runtimeSelectedDtbVerified": False,
        "note": "Owner-reported verification recorded in evidence.json, not fresh "
                "hash checks by this readiness script; physical load/handoff open.",
    }


def gate(stage: int, name: str, state: str, detail: str, next_proof: str) -> dict:
    if state not in {"COMPLETE", "PARTIAL", "OPEN", "BLOCKED", "DEFERRED"}:
        raise GateError(f"invalid gate status {state}")
    return {"stage": stage, "title": name, "state": state,
            "evidence": detail, "nextProof": next_proof}


def analyze(evidence: dict, artifacts: Path, source: Path, repo: Path) -> dict:
    validate_evidence(evidence)
    actual = artifacts_check(evidence, artifacts)
    src = source_check(source)
    btf = btf_candidates(artifacts / "kernel.bin") if (
        actual["kernel.bin"]["state"] == "MATCH") else {
            "status": "NOT_VERIFIED", "candidates": []}
    factory = stage4_factory_evidence(evidence)
    device = evidence.get("hxl1LiveBootSecurityState20261010", {})
    elf = artifacts / "hxl1-research/vmlinux-stock.elf"
    nm = artifacts / "hxl1-research/vmlinux-stock.nm"
    binary = evidence.get("originalFirmwareBinaryVerification", {})
    inc = binary.get("elfRecovery", {}).get("instructionCorrelation", {})
    source_audit = evidence.get("hxl1RtmutexFixReferenceAudit", {})
    audited = source_audit.get("ownerAuditExecution", {}).get("status") == (
        "PASS_SOURCE_AUDIT_ONLY")
    app = evidence.get("nativeIdentityProbe", {})
    identity = (device.get("model") == MODEL
                and device.get("kernel") == KERNEL
                and app.get("verifiedHardwareExecution") is True)
    raw_ok = all(item["state"] == "MATCH" for item in actual.values())
    src_ok = all(item["state"] == "MATCH" for item in src.values())
    # Original extracted ELF is from the original kernel and is an analysis
    # artifact, NOT a runtime address oracle.
    elf_available = elf.is_file() and nm.is_file()
    code_corr = inc.get("tested", []) if isinstance(inc, dict) else []
    has_binary_corr = bool(code_corr) and all(
        entry.get("equal") is True for entry in code_corr)
    # Explicit full layout and physical load evidence must be owner verified.
    struct_verified = False
    physical_load_verified = False
    slide_verified = False
    target_header = repo / "src/targets" / PROFILE / "target.h"
    fingerprint = repo / "src/targets" / PROFILE / "p0_fingerprint.h"
    target_available = target_header.is_file() and fingerprint.is_file()
    support = repo / "support/targets-v3.json"
    published = False
    if support.is_file():
        body = support.read_text(errors="replace")
        published = (FIRMWARE in body or MODEL in body)
    if published:
        raise GateError("STOP: unverified HXL1 detected in production support feed")

    statuses = [
        gate(1, "Exact firmware identity",
             "COMPLETE" if identity else "PARTIAL",
             "Owner ADB: stock HXL1, locked green boot, enforcing SELinux, "
             "shell UID 2000; previous native identity test",
             "Reconfirm only if firmware/build changes"),
        gate(2, "Stock firmware and source provenance",
             "COMPLETE" if raw_ok and src_ok else "PARTIAL",
             "Original 3 retained artifacts: " +
             ", ".join(f"{name}={entry['state']}" for name, entry in actual.items()) +
             "; original source 2 pinned hash checks: " +
             ", ".join(f"{name}={entry['state']}" for name, entry in src.items()),
             "Preserve exact original files; establish booted RAM identity "
             "only if necessary and authorized"),
        gate(3, "Symbol/structure provenance",
             "PARTIAL" if elf_available and has_binary_corr and audited
             else "OPEN",
             f"Stock recovered ELF/NM files present={elf_available}; "
             f"raw instruction correlation in owner evidence={has_binary_corr}; "
             f"source fix audit passed={audited}; "
             f"BTF scan={btf['status']}; "
             "complete verified 4.19 object layouts are missing",
             "Resolve exact layouts from target source plus independent binary "
             "or matching debugging information; do not use cross-device offsets"),
        gate(4, "Physical load and BL handoff",
             "COMPLETE" if physical_load_verified else "OPEN",
             ("Owner manifest: exact HXL1 BL/ELF verified="
              f"{factory['ownerManifestVerifiesExactHxl1BL']}; "
              "boot v2 and embedded hashes verified="
              f"{factory['ownerManifestVerifiesBootV2AndEmbeddedPayloads']}; "
              "four FDT semantic streams verified="
              f"{factory['ownerManifestVerifiesFourFdtTokenStreams']}. "
              "Neither ELF PT_LOAD segments nor stock boot header kernel_addr "
              "establish the actually booted Linux physical base."),
             ("Investigate original Qualcomm bootloader's selected DTB and "
              "physical Android kernel handoff with independent read-only "
              "evidence; do not reuse a bootloader ELF PT_LOAD address.")
             if factory["ownerManifestVerifiesExactHxl1BL"]
             else ("Verify exact HXL1 BL archive provenance and investigate "
                   "original boot.img DTBs, then establish physical handoff "
                   "without using another device's load assumptions.")),
        gate(5, "Per-build slide and runtime prerequisites",
             "COMPLETE" if slide_verified else "OPEN",
             "Stock KASLR, trace-event ID, worker return and original P0 page "
             "fingerprint parameters not proven for live HXL1",
             "Independently validate only the exact kernel's runtime interfaces; "
             "no imported constants or physical memory assumptions"),
        gate(6, "Native HXL1 target and payload package",
             "PARTIAL" if target_available else "OPEN",
             f"Native target header exists={target_header.is_file()}; "
             f"fingerprint header exists={fingerprint.is_file()}; "
             "firmware-locked identity-only diagnostic already exists",
             "Finish exact-specific implementation and verified device behavior "
             "before labeling a compiled payload functional"),
        gate(7, "KernelSU Linux 4.19 port",
             "BLOCKED",
             "CONFIG_MODULE_SIG_FORCE=y; CONFIG_KPROBES=n; "
             "CONFIG_FUNCTION_TRACER=n; KDP/RKP/DEFEX enabled",
             "Independently validate 4.19 hook ABI, genuine authorization to "
             "load code and Samsung security compatibility"),
        gate(8, "Application and support feed",
             "BLOCKED",
             "Exact profile intentionally absent from targets-v3.json; "
             "model/kernel-prefix matching is insufficient",
             "Keep research profile out of production until independently "
             "validated hardware, firmware and recovery gates pass"),
        gate(9, "Retention, recovery and release",
             "DEFERRED",
             "Original kernel/boot evidence preserved; no physical recovery "
             "or working release verification established",
             "Preserve all originals; document authorized recovery/test device "
             "and only then consider cleanup"),
    ]
    return {
        "schemaVersion": 1,
        "profile": PROFILE,
        "firmware": FIRMWARE,
        "kernel": KERNEL,
        "source": "docs/PORTING.md + exact HXL1 evidence; offline audit",
        "gates": statuses,
        "artifactIntegrity": actual,
        "sourceIntegrity": src,
        "factoryStage4EvidenceFromManifest": factory,
        "rawBtfSearch": btf,
        "recoveredElfFilesLocated": elf_available,
        "nativeTargetRegistered": target_available,
        "includedInProductionFeed": published,
        "completedStages": [i["stage"] for i in statuses
                            if i["state"] == "COMPLETE"],
        "unresolvedStages": [i["stage"] for i in statuses
                            if i["state"] != "COMPLETE"],
        "payloadPortCompleted": False,
        "ghostLockRuntimeValidated": False,
        "temporaryRootVerified": False,
        "kernelSuLoaded": False,
        "phoneChanged": False,
        "note": "No exploit, root, module, or flash test. Never interpret "
                "COMPLETE identity/firmware checks as payload completion.",
    }


def summary(data: dict) -> str:
    rows = [
        "# Galaxy S20+ HXL1 — nine-stage porting readiness",
        "",
        "Research-only; no active root payload or KernelSU load is asserted.",
        "",
        "| Stage | Gate | Status | Proof still needed |",
        "|---:|---|---|---|",
    ]
    for g in data["gates"]:
        rows.append(f"| {g['stage']} | {g['title']} | {g['state']} "
                    f"| {g['nextProof']} |")
    f4 = data["factoryStage4EvidenceFromManifest"]
    rows += [
        "", "## Factory firmware progress (owner-attested manifest)", "",
        "- Exact original HXL1 BL, extracted ABL/XBL ELF: " +
        str(f4["ownerManifestVerifiesExactHxl1BL"]),
        "- Original stock boot.img v2 and embedded kernel/ramdisk/DTB: " +
        str(f4["ownerManifestVerifiesBootV2AndEmbeddedPayloads"]),
        "- Four original FDT semantic token streams: " +
        str(f4["ownerManifestVerifiesFourFdtTokenStreams"]),
        "- Actual physical Linux kernel handoff: **NOT VERIFIED**",
        "- Bootloader-selected runtime DTB: **NOT VERIFIED**",
        "", "The manifest records the owner's prior hash-checked WSL runs; "
        "this readiness run does not re-hash the 89 MiB original BL archive.",
    ]
    rows += ["", "## Verified local inputs", ""]
    for name, item in data["artifactIntegrity"].items():
        rows.append(f"- Original {name}: {item['state']}")
    for name, item in data["sourceIntegrity"].items():
        rows.append(f"- Original source {name}: {item['state']}")
    rows.extend([
        f"- Original kernel raw BTF: {data['rawBtfSearch']['status']}",
        f"- Recovered ELF and NM paths: "
        f"{'available' if data['recoveredElfFilesLocated'] else 'missing'}",
        "",
        "## Decision",
        "",
        "**Not a functional root payload.** Next finish exact HXL1 object "
        "layout provenance and physical boot handoff before evaluating "
        "native target integration. Neither a locked bootloader nor "
        "source-level CVE evidence alone proves or disproves GhostLock "
        "runtime exploitation. KernelSU remains a separate integration gate.",
        "",
    ])
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--evidence", type=Path, default=EVIDENCE)
    ap.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS)
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    ap.add_argument("--repo", type=Path, default=ROOT)
    ap.add_argument("--output", type=Path,
                    default=DEFAULT_ARTIFACTS / "hxl1-research/port-readiness.json")
    args = ap.parse_args()
    vendor = args.source.expanduser().resolve()
    output = args.output.expanduser().resolve()
    repo = args.repo.expanduser().resolve()
    inputs = (
        vendor, repo / "src", repo / "support",
        args.artifacts.expanduser().resolve(),
    )
    if any(output == path or path in output.parents
           for path in inputs if path != args.artifacts.expanduser().resolve()):
        ap.error("Refusing to write readiness output under source, app, or support trees")
    if output.suffix != ".json":
        ap.error("--output must be a .json filename")
    try:
        evidence = json.loads(args.evidence.expanduser().read_text())
        report = analyze(evidence, args.artifacts.expanduser().resolve(),
                         vendor, repo)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        output.with_suffix(".md").write_text(summary(report))
    except (OSError, ValueError, GateError) as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2
    for row in report["gates"]:
        print(f"[{row['state']}] stage {row['stage']}: {row['title']}")
    print(f"[BTF] {report['rawBtfSearch']['status']}")
    print(f"[report] {output}")
    print(f"[report] {output.with_suffix('.md')}")
    print("[LIMIT] Research-stage port only; neither root payload nor KSU ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
