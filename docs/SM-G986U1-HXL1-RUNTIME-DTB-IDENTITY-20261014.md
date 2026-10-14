## October 14, 04:30 UTC — live ADB property parser stopped (fixed to retain diagnostic)

The owner ran `tools.test_y2q_hxl1_runtime_dtb_identity` on WSL: **12/12 PASS**. A subsequent authorized unprivileged ADB probe failed with:

```
[STOP] FDT root property contains unsafe/nonprintable bytes
cat: ...hxl1-live-dtb-root-20261014T043012Z.json: No such file or directory
```

The old code read the root `model` and `compatible` byte streams, then rejected any component containing `str.isprintable() == False` *before* writing a report. The console error lacks the offending property name or byte value. **This establishes a parser limit, not a failed or successful original DTB candidate match.** Never guess the nonprintable character's cause (newline, carriage return, malformed string, etc.) without raw evidence.

Committed diagnostic-mode correction: `tools/y2q_hxl1_runtime_dtb_identity.py` now identifies the failing field and emits a fresh structured `ROOT_PROPERTY_PARSE_REQUIRES_REVIEW` JSON on malformed UTF-8, unexpected controls or other invalid model/compatible forms. It preserves only bounded first/last raw-property hex, SHA-256, lengths and first non-NUL control offset. No device serial, IMEI, arbitrary filesystem content or memory dump is captured. **It does not silently strip malformed data**, and does not promote a candidate match on this path. It returns a nonzero status *after* writing the diagnostic JSON. Six synthetic cases expand the existing 12 to 18; new CI/owner execution still needs to verify them.

Run a single fresh **read-only** retry on the already-authorized handset:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_runtime_dtb_identity

OUT="$HOME/s20-artifacts/hxl1-research/hxl1-live-dtb-diagnostic-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 tools/y2q_hxl1_runtime_dtb_identity.py --output "$OUT"
RET=$?
echo "probe exit: $RET"
if test -s "$OUT"; then cat "$OUT"; else echo "ADB property read/evidence preflight failed before report creation"; fi
```

The diagnostic report is expected even if the parse step exits with status 2. Review `parseError`, `rawPropertyDiagnostics.model.firstControlByteExcludingNul` and the corresponding compatible property; the raw prefix hex then distinguishes a genuine embedded FDT control byte from ADB transport artifacts. No normalization or bootloader-selected DTB inference should be made until the uploaded diagnostic is examined.

**Stage 4 remains OPEN**, physical Linux kernel base and runtime DTB selection unverified; KernelSU remains blocked.

---

# HXL1 authoritative readiness accepted; Stage 4 live DTB root identity

2026-10-14 UTC. Research-only; this does not run an exploit, load a module, or modify firmware.

## Owner accepted report

The uploaded readiness-authority-20261014T042254Z.json has independently rehashed SHA-256:

    0bc7f1cdf4824e72e443353fdf721d032a193226225c7b1e37edf3ad5c196483

The owner report records portingReadinessReport=AGREES_ALL_NINE_STAGES. The remaining check results are manifest=PASS_STATIC_PINS_NO_RAW_REHASH, selectNumerics=CORROBORATED_STATIC_ONLY, debugArtifactScan=BOUNDED_COMPLETE_NOT_OEM_AUTHENTICATED, and unsearchedDeeperDirectories=895.

The stages remain COMPLETE, COMPLETE, PARTIAL, OPEN, OPEN, OPEN, BLOCKED, BLOCKED, DEFERRED. The owner report expressly records factory compiler-local identity, physical Linux handoff, root/KernelSU and production feed as unverified/not allowed. Its original input report digests are:

- Evidence manifest: d12ac8a1f7f29e8d106f87cb439cb75d60aec4253c50d6b525c2cefdcdb49303
- Authoritative readiness report: 933da679f2db6aa1db2d480bfdaa1842ace6f275bf8ce8dd89e7f3ea779c9ef8
- Select crosswalk report: f1c5114692a059ebc1c5d1542af19170640989054b998697c26ca0f7eb21a478
- OEM debug scan report: fc08987fe6a6a3f217e7a5d563ccce962ec0adf29963500a9bec13faeb0f304a

A structured acceptance checkpoint is stored in research/y2q-G986U1UESCHXL1/owner-readiness-authority-20261014T042254Z.json.

## Next Stage 4 evidence: handset device-tree root identity

The original HXL1 firmware contains four semantically valid FDT streams; three have recorded root models:

| Candidate | Stock root model | Compatible |
|---|---|---|
| 1 | Qualcomm Technologies, Inc. kona v2.1 SoC | qcom,kona |
| 2 | Qualcomm Technologies, Inc. kona v2 SoC | qcom,kona |
| 3 | Qualcomm Technologies, Inc. kona v1 SoC | qcom,kona |
| 4 | unknown/no root model in minimal original FDT | absent |

The existing read-only script tools/y2q_hxl1_runtime_dtb_identity.py uses already-authorized ADB to read only the model, compatible, build identity and uname from the physical handset. It compares against SHA-pinned original FDT evidence. No IMEI, phone serial number or device tree memory address is requested; no phone write/privilege operation occurs. On a device with read access to standard root device-tree properties, run this host-side command once:

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_runtime_dtb_identity

OUT="$HOME/s20-artifacts/hxl1-research/hxl1-live-dtb-root-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 tools/y2q_hxl1_runtime_dtb_identity.py --output "$OUT"
cat "$OUT"
~~~

Use --adb-serial only if multiple already-authorized ADB transports exist. Output is restricted to a fresh path outside the repository. The tool fails closed on input evidence drift or inaccessible properties.

**Do not promote Stage 4 if the model string matches one candidate.** A root model and qcom,kona compatible relationship is only a source/runtime metadata comparison. A matching original FDT byte hash, applied overlays, physical handset bootloader handoff, and actual physical Linux kernel load base are NOT thereby established. No factory ABI stack slots, runtime GhostLock exploit, root or KernelSU load are certified.

The new test file contains twelve synthetic methods; the dedicated GitHub Actions workflow has been added, but its successful completion is not yet observed. All original stage states remain unchanged.
