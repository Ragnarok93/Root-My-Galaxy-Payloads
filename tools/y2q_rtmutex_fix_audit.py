#!/usr/bin/env python3
"""Read-only HXL1 RT-mutex source and published upstream fix comparison.

Accepts only original Samsung sources matching the two pinned SHA-256 hashes.
Parses the user's two previously downloaded public patch transcripts.
Does not modify kernel source, call ADB, run a futex or build any kernel.

This is a SOURCE-LEVEL comparison, not CVE runtime/exploit/root evidence.
The 2026 follow-up regression CVE-2026-53163 was introduced by the
first fix, and must not independently be attributed to old vendor 4.19.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCES = {
    "kernel/locking/rtmutex.c": "36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9",
    "kernel/futex.c": "493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5",
}
REFERENCES = {
    "ownership": {
        "filename": "01-waiter-task-fix.txt",
        "url": "https://lists.ubuntu.com/archives/kernel-team/2026-July/169898.html",
        "cve": "CVE-2026-43499",
        "commit": "3bfdc63936dd4773109b7b8c280c0f3b5ae7d349",
    },
    "followup": {
        "filename": "02-unenqueued-waiter-fix.txt",
        "url": "https://lists.ubuntu.com/archives/kernel-team/2026-July/170235.html",
        "cve": "CVE-2026-53163",
        "commit": "40a25d59e85b3c8709ac2424d44f65610467871e",
    },
}
# Match complete changed lines in patch transcripts, stripping whitespace.
REQUIRED_DIFFS = {
    "ownership": {
        "wrongTaskPiLockRemoved": (r"^-raw_spin_lock\(&current->pi_lock\);$",),
        "waiterTaskPiLockAdded": (r"^\+raw_spin_lock\(&waiter_task->pi_lock\);$",),
        "wrongTaskBlockedOnRemoved": (r"^-current->pi_blocked_on=NULL;$",),
        "waiterTaskBlockedOnAdded": (r"^\+waiter_task->pi_blocked_on=NULL;$",),
        "waiterTaskAssociated": (r"^\+structtask_struct\*waiter_task=waiter->task;$",),
        "priorityChainUsesWaiterTask": (
            r"^\+.*next_lock,NULL,waiter_task\);$",
            r"^\+.*waiter_task\);$",
        ),
    },
    "followup": {
        "neverEnqueuedGuard": (r"^\+if\(!waiter_task\).*$",),
        "cleanupAnyNonzeroRemoved": (r"^-if\(unlikely\(ret\)\)$",),
        "cleanupNegativeOnlyAdded": (r"^\+if\(unlikely\(ret<0\)\)$",),
    },
}
DEFAULT_REPORT = Path.home() / "s20-artifacts/hxl1-research/rtmutex-fix-review"
SOURCE_INDICATORS = {
    "currentPiLock": ("kernel/locking/rtmutex.c", 1068, 1120, r"\bcurrent->pi_lock\b"),
    "currentBlockedOn": ("kernel/locking/rtmutex.c", 1068, 1120, r"\bcurrent->pi_blocked_on\b"),
    "proxyWrapperAnyNonzeroCleanup": (
        "kernel/locking/rtmutex.c", 1790, 1811,
        r"if\s*\(\s*unlikely\s*\(\s*ret\s*\)\s*\)"),
    "futexProxyCall": ("kernel/futex.c", 2145, 2170, r"\brt_mutex_start_proxy_lock\s*\("),
    "waiterTaskAssignment": ("kernel/locking/rtmutex.c", 949, 971, r"waiter->task\s*=\s*task"),
    "waiterEnqueue": ("kernel/locking/rtmutex.c", 954, 971, r"\brt_mutex_enqueue\s*\("),
}


class AuditError(Exception):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_original(vendor: Path) -> dict[str, str]:
    hashes = {}
    for relative, expected in SOURCES.items():
        source = vendor / relative
        if not source.is_file():
            raise AuditError(f"Missing Samsung file: {source}")
        actual = digest(source)
        if actual != expected:
            raise AuditError(f"STOP: Samsung hash mismatch for {source}: {actual}")
        hashes[relative] = actual
    return hashes


def inspect_source(vendor: Path) -> dict[str, dict[str, object]]:
    findings = {}
    for label, (relative, first, last, expression) in SOURCE_INDICATORS.items():
        lines = (vendor / relative).read_text(errors="replace").splitlines()
        matches = [
            {"line": n, "text": lines[n - 1].strip()}
            for n in range(first, min(last, len(lines)) + 1)
            if re.search(expression, lines[n - 1])
        ]
        findings[label] = {"found": bool(matches), "matches": matches, "file": relative}
    return findings


def strip_diff_whitespace(line: str) -> str:
    # Only remove whitespace, keeping + and - markers intact.
    return re.sub(r"\s+", "", line)


def inspect_reference(path: Path, key: str) -> dict[str, object]:
    if not path.is_file():
        raise AuditError(f"Missing patch text: {path}")
    patch = path.read_text(encoding="utf-8", errors="replace")
    if "diff --git" not in patch or "remove_waiter" not in patch:
        raise AuditError(f"Not a recognizable patch transcript: {path}")
    changed_lines = [
        strip_diff_whitespace(line)
        for line in patch.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    results = {
        name: any(
            re.search(pattern, line)
            for pattern in alternatives for line in changed_lines
        )
        for name, alternatives in REQUIRED_DIFFS[key].items()
    }
    return {
        "sourceFile": str(path),
        "sourceSha256": digest(path),
        "referenceUrl": REFERENCES[key]["url"],
        "cve": REFERENCES[key]["cve"],
        "upstreamCommit": REFERENCES[key]["commit"],
        "diffChecks": results,
        "allExpectedEditsFound": all(results.values()),
    }


def compare(vendor: Path, reference_dir: Path) -> dict[str, object]:
    pinned_hashes = validate_original(vendor)
    references = {
        key: inspect_reference(reference_dir / data["filename"], key)
        for key, data in REFERENCES.items()
    }
    original = inspect_source(vendor)
    return {
        "schemaVersion": 1,
        "firmware": "SM-G986U1 / G986U1UESCHXL1",
        "stockKernel": "4.19.113-27095354",
        "samsungSourceHashesVerified": True,
        "samsungSourceHashValues": pinned_hashes,
        "originalCodeIndicators": original,
        "patchReferences": references,
        "ownershipMismatchSourcePattern": all(
            original[k]["found"] for k in (
                "currentPiLock", "currentBlockedOn", "proxyWrapperAnyNonzeroCleanup",
                "futexProxyCall", "waiterTaskAssignment", "waiterEnqueue")
        ),
        "publishedFixDiffsComplete": all(
            r["allExpectedEditsFound"] for r in references.values()
        ),
        "interpretation": [
            "Original HXL1 source contains the current/waiter ownership pattern.",
            "The published initial fix changes cleanup to waiter_task.",
            "The published follow-up guards never-enqueued waiters and ret < 0.",
            "The follow-up CVE was introduced by the initial fix; it is not "
            "independently assigned to the old Samsung 4.19 tree by this audit.",
            "Upstream Linux 4.19.325 predates both 2026 corrections; QEMU "
            "success only establishes healthy guest kernel primitives.",
        ],
        "runtimeCveReproduced": False,
        "onPhoneRootVerified": False,
        "kernelSuValidated": False,
        "deviceModified": False,
    }


def markdown(report: dict[str, object]) -> str:
    text = [
        "# HXL1 RT-mutex patch comparison (source-only)",
        "",
        "Samsung stock source SHA-256: VERIFIED, both files.",
        "",
        "## Original Samsung source indicators",
        "",
        "| Indicator | Located | First matching location |",
        "|---|---|---|",
    ]
    for label, finding in report["originalCodeIndicators"].items():
        matches = finding["matches"]
        location = f"{finding['file']}:{matches[0]['line']}" if matches else "—"
        text.append(f"| {label} | {finding['found']} | {location} |")
    text.extend(["", "## Published fix diff validation", ""])
    for key, patch in report["patchReferences"].items():
        text.append(f"### {key}: {patch['cve']}")
        text.append(f"Reference: {patch['referenceUrl']}")
        text.append(f"Commit: {patch['upstreamCommit']}")
        for name, found in patch["diffChecks"].items():
            text.append(f"- {name}: {'FOUND' if found else 'NOT FOUND'}")
        text.append("")
    text.extend([
        "## Evidence limits",
        "",
        "This is a read-only code and diff comparison, not a CVE reproduction. "
        "It does not demonstrate a memory corruption primitive, root access, "
        "kernel loading, KernelSU, or Snapdragon 865 runtime equivalence.",
        "",
        "CVE-2026-53163 is a follow-up regression introduced by the original fix; "
        "do not label Samsung 4.19 independently affected without evidence.",
        "",
    ])
    return "\n".join(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", type=Path,
                        default=Path.home() / "src/samsung-y2q-hxl1-stock")
    parser.add_argument("--references", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT / "audit.json")
    args = parser.parse_args()
    vendor = args.vendor.expanduser().resolve()
    refs = args.references.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if output.suffix != ".json":
        parser.error("Report filename must end in .json")
    if output == vendor or vendor in output.parents:
        parser.error("Refusing to write any output into original Samsung tree")
    try:
        report = compare(vendor, refs)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        md = output.with_suffix(".md")
        md.write_text(markdown(report))
        print("[PASS] original Samsung source: SHA-256 matched 2/2")
        for key, ref in report["patchReferences"].items():
            print(f"[{'PASS' if ref['allExpectedEditsFound'] else 'REVIEW'}] "
                  f"{key} published diff expected edits")
        print(f"[{'PASS' if report['ownershipMismatchSourcePattern'] else 'REVIEW'}] "
              "Samsung source ownership/rollback indicator coverage")
        print(f"[report] {output}")
        print(f"[report] {md}")
        print("[LIMIT] source-only; no GhostLock triggering or root/KSU claim")
        return 0 if report["publishedFixDiffsComplete"] and (
            report["ownershipMismatchSourcePattern"]) else 3
    except (OSError, AuditError) as error:
        print(f"[STOP] {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
