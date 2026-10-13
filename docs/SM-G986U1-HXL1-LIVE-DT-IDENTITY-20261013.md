## October 13, 13:02 UTC — owner verified 28/28 regression tests, permission denied confirmed

Owner WSL console result:

```text
Ran 28 tests in 0.018s
OK
[STRICT DEVICE IDENTITY] MATCH
[BOOT STATE] REPORTED_LOCKED
[RUNTIME DT ROOT IDENTITY] RUNTIME_PROPERTIES_PERMISSION_DENIED
[RUNTIME DT MODEL] None
[RUNTIME DT COMPATIBLE] None
[DT READ STATES] PERMISSION_DENIED PERMISSION_DENIED
[LEGACY ADB ERRORS CORRECTED] dtModel, dtCompatible
[PHYSICAL BOOTLOADER HANDOFF VERIFIED] NO
[ROOT VERIFIED] NO
[REPORT] /home/main/s20-artifacts/hxl1-research/device-fdt-comparison-20261013T130243473179Z/device-fdt-comparison.md
```

**Resolution:** The `NO_ROOT_IDENTITY_MATCH` result was a false mismatch caused by ADB shell `cat` permission-error text presented as successful data. The corrected test and saved snapshot reconciliation passed, and current firmware identity/locked boot state are unchanged. The original four DTBs are intact, but the running DTB selection cannot be verified from the inaccessible `/proc/device-tree` fields. Do **not** repeat these tests or request elevated reads solely for this mismatch.

### Next hard blockers: true execution chain, not ABI or DTB

**HXL1 stock security controls**, from `research/y2q-G986U1UESCHXL1/evidence.json` and `tools/y2q_porting_readiness.py`:

| Kernel control | HXL1 | Practical consequence |
|---|---|---|
| `CONFIG_MODULES` | `y` | Module machinery is compiled in, but loading is independently restricted |
| `CONFIG_MODVERSIONS` | `y` | Imported symbols require compatible versioning/ABI |
| `CONFIG_MODULE_SIG_FORCE` | `y` | Ordinary unsigned modules are rejected under stock policy |
| `CONFIG_KPROBES` | `n` | Standard kprobe hook strategy is unavailable |
| `CONFIG_FUNCTION_TRACER` | `n` (recorded elsewhere in evidence) | Function-tracer-based fallback is unavailable |
| `CONFIG_UH_RKP`, `CONFIG_KDP_CRED`, `CONFIG_SECURITY_DEFEX` | `y` | Samsung-specific restrictions demand independent compatibility review |

**Do not assume that transient root gives permission to load an unsigned KernelSU module.** The existing Samsung KernelSU patch family also documents hardware-specific faults caused by direct KDP credential operations and RKP-protected write attempts, as recorded in `kernelsu/README.md`. Those successes belong to other kernel/device combinations and cannot be transferred to HXL1 without verification.

**Concrete cross-device ABI mismatch:** upstream GhostLock 4.19 `src/targets/alioth-4.19.157-perf/target.h` uses `TASK_PI_LOCK_OFF=0x8b4` and `TASK_PI_BLOCKED_ON_OFF=0x8d8`. HXL1 Samsung-source comparison candidates are `task_struct.pi_lock=0x8c8` and `pi_blocked_on=0x8f8` (13/13 Clang10/18 candidate parity). An unchanged Redmi payload would be using demonstrably different task-structure offsets, aside from unproven allocator, memory map, address slide, and Samsung security assumptions.

**Upstream blocker:** GhostLock's original `ccp-p/ghostlock-cve-2026-43499-4.19-k40/docs/status.md` lists its root chain as blocked and records unsuccessful device-root trials; it does not demonstrate a successful complete root solution for its own 4.19 target. HXL1 has no demonstrated privilege escalation or KernelSU initialization.

### Decision

Close the unprivileged DTB comparison as **INACCESSIBLE, NOT MISMATCHED** and do not burn another owner cycle on static Clang or DTB reruns. The key remaining tasks are independent of the completed 28-test suite:

1. Independently demonstrate exploit applicability and successful privilege transition on the exact stock Samsung kernel before labeling a native GhostLock port functional.
2. Independently establish a genuinely authorized and compatible KernelSU loading mechanism under signature enforcement, unavailable kprobes, and Samsung KDP/RKP/DEFEX. A loader compiled for a different model/KMI does not meet this gate.
3. Keep the bootloader locked/reported state separate from physical firmware handoff; neither ordinary ADB nor stock boot.img header fields establish kernel load location.
4. Keep support-feed integration blocked until hardware root, module, reboot/recovery, and versioned-artifact tests actually pass.

**No functional root solution was developed, run or proven by this checkpoint.**

---

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
