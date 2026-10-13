## October 13, 12:36 UTC — resolve false device-tree mismatch

The user's original read-only live snapshot conclusively showed **ADB/Android access denial**, not differing DTB identifiers:

```text
dtModel state=READ value='cat: /proc/device-tree/model: Permission denied' error=''
dtCompatible state=READ value=['cat: /proc/device-tree/compatible: Permission denied'] error=''
```

The first snapshot collector accepted remote `cat` error text in `stdout` because the *host ADB invocation* returned 0, and serialized it as `READ`. The downstream root-property matcher compared those literal error strings to the stock FDT models and `qcom,kona`, yielding the **false** `NO_ROOT_IDENTITY_MATCH`. The original firmware and physical device identity never failed.

Fixes:

- `tools/y2q_hxl1_live_identity_snapshot.py`: recognize bounded shell `cat` errors for the exact `/proc/device-tree/model` and `/proc/device-tree/compatible` paths even with process exit code 0; produce `PERMISSION_DENIED` with `value=null`, preserving diagnostic text in `error`. Handle nonexistent files as `UNAVAILABLE`.
- `tools/y2q_hxl1_device_fdt_reconcile.py`: normalize the **historical** previously saved bad `READ` records at comparison time. No modification to the original JSON, and no additional ADB call. On this evidence, expected classification is `RUNTIME_PROPERTIES_PERMISSION_DENIED`.
- Regression tests cover both original error strings, both current correctly labeled reads, partially unavailable input and harmless valid model text containing a non-error 'Permission denied' substring.

**Do not** use the prior `NO_ROOT_IDENTITY_MATCH` result as evidence that HXL1 stock DTBs do not match the running device. All four stock DTBs remain hash- and structure-verified. Their live selection is **UNDETERMINED** through unprivileged root-property reads; device state is `REPORTED_LOCKED`. Firmware identity remains HXL1 MATCH. Root and bootloader physical Linux handoff remain UNVERIFIED.

Recommended targeted test (no Clang, Ghidra, firmware extraction or new ADB):
```sh
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_live_identity_snapshot tools.test_y2q_hxl1_device_fdt_reconcile
python3 tools/y2q_hxl1_device_fdt_reconcile.py
```

The new report should include `[RUNTIME DT ROOT IDENTITY] RUNTIME_PROPERTIES_PERMISSION_DENIED`, `[DT READ STATES] PERMISSION_DENIED PERMISSION_DENIED`, and `[LEGACY ADB ERRORS CORRECTED] dtModel, dtCompatible`. New logic and tests are committed, but owner WSL result has not yet been observed.

---

# HXL1 physical-device identity follow-up — 2026-10-13

## Owner-host result accepted (no root claim)

The owner ran the existing unprivileged read-only `tools/y2q_hxl1_live_identity_snapshot.py` against a connected S20+:

```
Ran 10 tests in 0.008s
OK
[DEVICE IDENTITY MATCHES HXL1] YES
[BOOTLOADER HANDOFF PROVEN] NO
[ROOT VERIFIED] NO
[SNAPSHOT] /home/main/s20-artifacts/hxl1-research/device-identity-20261013T121400921888Z/identity.json
```

The console confirms device identity consistency (model, HXL1 build token, arm64, Linux 4.19.113) and successful unprivileged ADB collection. The **full device snapshot was not uploaded** during this checkpoint; do not invent its `dtModel`, `dtCompatible`, `ro.boot.*` values, or the bootloader-selected DTB.

## Next useful local reconciliation: no device calls or repeated REA/Clang

`tools/y2q_hxl1_device_fdt_reconcile.py` consumes the newest *existing* `device-identity-*/identity.json` automatically. It independently SHA-pins original `boot.img` and embedded DTB and reuses `tools/y2q_stock_fdt_semantic_audit.py` to compare the runtime root model and compatible strings against four known original FDT candidates. It also compares the snapshot's model, firmware, product fingerprint, bootloader label, and kernel release against the tracked original `research/y2q-G986U1UESCHXL1/evidence.json`.

```sh
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_device_fdt_reconcile
python3 tools/y2q_hxl1_device_fdt_reconcile.py
```

Report: `~/s20-artifacts/hxl1-research/device-fdt-comparison-<timestamp>/device-fdt-comparison.md` and `device-fdt-comparison.json`.

The source code and 10 regression tests are committed; a dedicated GitHub Actions workflow attempts to run its *synthetic* CI tests. The actual owner's physical-device JSON and original boot image are only on WSL. No successful owner run or GitHub CI result has yet been observed for this new tool.

## Strict evidence boundaries

- `ONE_MODEL_AND_COMPATIBLE_IDENTITY_MATCH` means **a matching root identity**, not an identical runtime DTB image. Bootloader changes and DT overlays can modify it.
- `COMPATIBLE_MATCH_ONLY` (e.g. `qcom,kona` shared by multiple trees) is explicitly ambiguous.
- Boot-state properties are *reported* Android properties; they do not establish hardware unlockability or firmware flashing permission.
- Confirming a bootloader-selected DTB model does not establish physical kernel load address, original firmware byte identity, KASLR, an exploitable GhostLock primitive, or KernelSU functionality.
- Our previous cross-compiler ABI comparison was **13/13 numeric candidate parity**; OEM member attribution and original byte-level runtime equivalence remain unfinished.
- The upstream K40 GhostLock repository's own documented root milestone remains blocked. A finished S20+ root cannot be inferred from its Redmi/OPPO target header or our HXL1 research objects.

**Status:** HXL1 firmware ID and provenance COMPLETE. Exact OEM structure attribution PARTIAL. Physical handoff and runtime privilege escalation UNVERIFIED. KernelSU deployment and support-profile release BLOCKED. No root or production payload claimed.
