# SM-G986U1 HXL1 bootloader unlock — independent research track

**Status (2026-10-11): RESEARCH ONLY. No unlock, modified image, unsigned boot or flash demonstrated.**

## Purpose and separation from KernelSU

The goal is to determine how the exact SM-G986U1/XAA `G986U1UESCHXL1` firmware
authenticates firmware flashing, decides whether the OEM lock can change, and
verifies images before execution. A kernel CVE exploit or KernelSU module is
**not a prerequisite for offline bootloader analysis**, and neither is a substitute
for a bootloader-unlock mechanism. Keep the two tracks independent.

## Verified HXL1 evidence we are reusing

- Owner-authenticated original BL TAR/MD5 has 27 members, length **92,600,434 bytes**,
  SHA256 `f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b`.
- Original extracted HXL1 `abl.elf`, `xbl.elf` and `xbl_config.elf` have
  separate hash-pinned ELF header audits in `tools/y2q_stock_bl_elf_audit.py`.
- The nested `LinuxLoader-HXL1.efi` AArch64 PE is independently byte-verified:
  SHA256 `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`.
- Firmware analysis already proves FDT/overlay composition and several **static**
  Linux-handoff candidates. It has **not** reconstructed the OEM unlock decision.
- Existing stock-device ADB metadata reported `ro.boot.flash.locked=1` and
  `ro.boot.vbmeta.device_state=locked`. None of these reports establishes
  an authorized change to hardware-backed lock state.

Primary notes: `docs/SM-G986U1-HXL1-ABL-FDT-BOOTCHAIN-20261011.md` and
`docs/SM-G986U1-HXL1-INVESTIGATION.md`.

## Comparator selection and limits

**First comparator:** SM-G9860, CSC **TGY** (Hong Kong), Android 13,
firmware `G9860ZHSCHYA1`, Jan 10 2025 build, security patch **2025-01-01**.
This aligns the OS and Android security-patch level with HXL1; it does **not**
guarantee matching boot-chain implementations, chipset configuration, bootloader
revisions, build provenance, signing keys, or rollback versions.

Firmware index and BL child-file listing:
- https://samfw.com/firmware/SM-G9860/TGY/G9860ZHSCHYA1
- https://samfw.com/firmware/SM-G9860/TGY

Reported BL child file:
`BL_G9860ZHSCHYA1_G9860ZHSCHYA1_MQB91116379_REV00_user_low_ship_MULTI_CERT.tar.md5.zip`.
Use an independently sourced authentic file; the scanner does **not** download
or cryptographically authenticate the G9860 firmware provenance on its own.
Record its measured digest when obtained and check matching Samsung model/build
metadata before interpreting cross-model binary differences.

Community observation for model choice:
https://xdaforums.com/t/recovery-unofficial-twrp-for-galaxy-s20-series-snapdragon.4157901/page-14
(developer reports G9860/G986N ordinarily unlockable, unlike G986U/U1/W).
This observation is not evidence of a bypass for HXL1.

## Implemented audit (host only)

- `tools/y2q_hxl1_bootloader_unlock_audit.py` checks the exact owner-measured
  HXL1 BL **size and SHA256** before reading archive members.
- It parses only nine named candidate components, rejects duplicate/nonregular
  entries, bounds LZ4 expansion, hashes each decompressed image, and captures
  ELF/vbmeta/raw classification plus ASCII/UTF-16 security-term leads.
- ABL/XBL are also scanned for nested EFI firmware volumes, FFS file GUIDs,
  and recognized AArch64 PE executables. Correlated GUIDs/hashes help choose
  modules for semantic comparison; a missing module in this bounded parser
  does **not** prove that executable code is absent (XBL may use gzip or
  unsupported vendor wrappers).
- When a separately supplied `BL_G9860*.tar.md5` is available, it generates
  per-component hash/format/size differences and comparative hint counts.
- A candidate string is **not** a verified xref, execution path, unlock branch,
  signature bypass, service access or security-policy decision.
- No actual G9860 bytes have been supplied/compared in this project so far.
- Optional analysis copies are written only under a separate output directory.
  Do **not** flash or boot any G9860 image on the G986U1.

### Execute against our existing original HXL1 BL (no comparator required)

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_bootloader_unlock_audit

FIRMWARE=/mnt/c/Users/Admin/Downloads/SAMFW.COM_SM-G986U1_XAA_G986U1UESCHXL1_fac
HXL1_BL="$FIRMWARE/BL_G986U1UESCHXL1_G986U1UESCHXL1_MQB90638722_REV00_user_low_ship_MULTI_CERT.tar.md5"
python3 tools/y2q_hxl1_bootloader_unlock_audit.py --hxl1-bl "$HXL1_BL"

cat ~/s20-artifacts/hxl1-research/bootloader-unlock/bootloader-unlock-candidates.md
```

Requires Python 3 and `lz4` Python module (e.g. in a disposable venv:
`python -m pip install lz4`). No root/ADB/phone connection is used.

### Compare once authentic G9860 BL is obtained

Extract only the *inner BL TAR/MD5* from the downloaded G9860 BL ZIP into a
separate host research directory. Do not replace stock HXL1 files.
Set `G9860_BL` to that extracted file and run:

```bash
python3 tools/y2q_hxl1_bootloader_unlock_audit.py \
  --hxl1-bl "$HXL1_BL" \
  --g9860-bl "$G9860_BL" \
  --export-binaries
```

Reports: `~/s20-artifacts/hxl1-research/bootloader-unlock/bootloader-unlock-candidates.{json,md}`.
Analysis-only binaries: `comparison-inputs/{HXL1,G9860}/`. When supported
nested UEFI modules are found, their recognized PE files are separately copied
as `comparison-inputs/{HXL1,G9860}/uefi-modules/{abl.elf,xbl.elf}/*.efi` with
FFS GUID and SHA256 prefix in the filename. Only matching GUIDs should be
compared in Ghidra after checking image architecture and module provenance.
The comparator is flagged `UNVERIFIED_COMPARATOR_PROVENANCE` until independent
firmware identity checks have been recorded. The report never asserts success.

## 2026-10-11 — owner HXL1 scan result and cached hotspot review

The owner ran the pinned HXL1 scanner on original BL firmware in WSL and obtained:

- All **12/12** initial regression tests PASS.
- Hash-pinned HXL1 BL archive accepted at SHA256
  `f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b`.
- Outer `abl.elf`: 0 narrow unlock strings / 0 AVB strings.
- Outer `xbl.elf`: 0 narrow unlock strings / **11** AVB strings.
- Outer `tz.mbn`: 0 narrow unlock strings / **8** AVB strings.
- Outer `uefi_sec.mbn`: 0 narrow unlock strings / **6** AVB strings.
- Outer `vaultkeeper.mbn`: 0 narrow unlock strings / 0 AVB strings.
- `vbmeta.img`: 0 unlock strings / 1 AVB string.
- Comparator: `COMPARATOR_NOT_PROVIDED`. No G9860 bytes inspected.

**Interpretation:** The outer-ELF string search is insufficient for ABL's
nested EFI modules and can miss logic implemented without text. It is
**not evidence that G986U1 lacks unlock code**. Avoid declaring XBL or
TrustZone's particular functions identified solely by string counts.

The original scanner's Markdown was updated to print its existing nested
UEFI inventory. **To inspect what the owner has already exported without
running the 92-MiB BL audit again**, use the new SHA-enforcing helper:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m unittest -v \
  tools.test_y2q_hxl1_bootloader_unlock_audit \
  tools.test_y2q_hxl1_bootloader_hotspots

python3 tools/y2q_hxl1_bootloader_hotspots.py

cat ~/s20-artifacts/hxl1-research/bootloader-unlock/hxl1-bootloader-hotspots.md
```

This reads only existing `bootloader-unlock-candidates.json` and
`comparison-inputs/HXL1/` exports. It re-verifies each extracted binary
against the saved SHA256, scans ASCII and UTF-16 strings, and creates:

- `hxl1-bootloader-hotspots.md`: ranked parent and EFI-module leads,
  candidate strings and **file offsets**, not virtual addresses.
- `hxl1-bootloader-hotspots.json`: counts, hashes, source relationships,
  and full bounded samples for later REA/Ghidra review.

The helper does **not** re-open the firmware archive, assert an OEM unlock
path, contact the phone, execute a firmware binary or use the comparator.
Missing exports or mismatched digests are errors, not silent omissions.

For a full scan including nested UI modules in the original audit's
Markdown, the original scanner can optionally be rerun. That is **not
required** for the cached hotspot analysis above.

**Next binary RE step:** use the named nested EFI file and original
file-offset candidates to conduct **qualified** Ghidra xrefs, then
inspect actual callers of verified-boot and OEM-lock-state services.
If zero candidates, proceed via known protocol GUIDs and entrypoint /
call graph discovery, not a speculative unlock conclusion.

---


## October 11 — REA/Ghidra automated security-path investigation

The owner executed the SHA-pinned HXL1 bootloader hotspot inventory
successfully: **13** verified firmware binaries. Crucially, the
*embedded UEFI applications* have more targeted evidence than the
outer ABL ELF string search:

- **Odin** (SHA256 09da14205be3e773f8b6ca9651fc9a1faabe871950b713ea79fc626e3c36de42):
  OEMLOCK, Custom Binary blocked by OEM Lock, Oem unlock value,
  flash unlock Failed, and Download Mode command processing.
- **LinuxLoader** (SHA256 5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003):
  Skipping boot verification when unlocked, read_is_device_unlocked,
  VaultKeeper app calls, and rollback service references.
- **VaultKeeper** (SHA256 614795b445c776859bdacdfe12ccc42bfe4cc47330b7b657adbb1730ce714183):
  VaultKeeper command processing and vendor daemon strings.
- **XBL and TZ** contain retail-unlock, RPMB and anti-rollback leads;
  these terms can refer to *other subsystems*, not the Samsung Android
  OEM unlock mechanism.

The strings do not establish code reachability, unlock feasibility,
a particular secure-world policy or a vulnerability.

### Automated implementation

The new host-only tools are:

- tools/y2q_hxl1_rea_security_audit.py
- tools/run_y2q_hxl1_rea_security_audit.sh
- tools/test_y2q_hxl1_rea_security_audit.py

They reuse the **existing** saved hotspot JSON and exported image copies,
rather than re-extracting or downloading firmware. Every source is checked
against its exact original HXL1 SHA256.

The script uses REA/Ghidra string searches, verifies returned analysis
coordinates, queries xrefs, resolves owning functions, validates the
reported function body, and records decompiled code excerpts. It also
generates a *manual security/vulnerability review queue* for suspect
copy APIs, external input, OEM lock branches, and secure-service calls.
Optional HighFunction def-use tracing is explicitly bounded.

Raw REA Evidence is checked for operation, Ghidra provider, selected
SHA256, ARM64 architecture, query parameters, and Evidence ID.
Mismatches fail closed. Failed commands preserve partial output and
stderr; they are never promoted to verified evidence. The earlier
hotspot report's **file offsets are not Ghidra virtual addresses**.

### First run: plan mode (no Ghidra operation)

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m unittest -v tools.test_y2q_hxl1_rea_security_audit

python3 tools/y2q_hxl1_rea_security_audit.py
cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/security-paths.md
~~~

### Run automated original-HXL1 static REA/Ghidra queries

~~~bash
bash tools/run_y2q_hxl1_rea_security_audit.sh
~~~

Initial execution limits literal searches to **three per selected module**,
to make the first Ghidra pass tractable. Once the first pass is confirmed,
the remaining original terms can be added incrementally while reusing
validated previous Evidence:

~~~bash
bash tools/run_y2q_hxl1_rea_security_audit.sh --seed-limit 6
~~~

The wrapper activates the existing WSL Node 24, REA and Ghidra
environment. The default targets are **Odin** and **LinuxLoader**.
More expensive secure-firmware formats are optional:

~~~bash
bash tools/run_y2q_hxl1_rea_security_audit.sh --include-secure
~~~

HighFunction value-flow exploration is disabled by default; enable
a small bounded sample after code functions have been identified:

~~~bash
bash tools/run_y2q_hxl1_rea_security_audit.sh --max-traces 2
~~~

Results are saved under:

    ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/

Read security-paths.md for a summary, security-paths.json for a
machine-readable ledger, and component subdirectories for original
REA search/xref/function/trace Evidence. The script may stop with
incomplete or provider-specific results; inspect the retained
.partial and stderr files without calling them successful.

### Actual security proof questions

1. Where does **OdinApp** get the current OEM lock status, and which
   callback decides whether to accept a custom binary?
2. Which service implements LinuxLoader's
   read_is_device_unlocked callback, and how are failures handled?
3. Are the decisions bound to VaultKeeper/TrustZone protected storage,
   or to firmware-local configuration?
4. Do the incoming Odin protocol parsers bound lengths and allocations,
   and is authentication checked *before* sensitive operations?
5. Which successful and failure branches are validated by actual
   Ghidra instructions instead of strings or pseudocode guesses?

Vulnerability investigation remains *static candidate triage* until
an actual reachable bug and safe, isolated reproducible input are
established. The tool **does not execute OEM firmware, fuzz the live
device, rewrite RPMB, patch ABL, flash a G9860 bootloader, or claim
bootloader unlock success**.

---


## October 11, 11:30 UTC — verified first Odin/LinuxLoader Ghidra pass

Owner-executed original HXL1 WSL run: **17** new REA operations;
**six** Ghidra search results; **five** Ghidra function dossiers;
**zero** reported errors. These are static original-binary code references,
not an unlock or a vulnerability.

| Module | Search string address | Verified reference source | Ghidra function |
|---|---|---|---|
| Odin: Oem unlock value | 0x83aa4 | 0x1ecc8 | 0x1ec00 |
| Odin: custom binary blocked by OEM Lock | 0x8297d | 0x1b3d4 | 0x1b6a8 |
| LinuxLoader: Skipping boot verification | 0xb2fa7 | 0x40f0 | 0x3f54 |
| LinuxLoader: read_is_device_unlocked | 0xb3662 | 0x59d4 | 0x5950 |
| LinuxLoader: device unlocked | 0xb2dc4 | 0x3f34 | 0x2274 |

The direct Ghidra xref count for the separate Odin OEMLOCK string at
0x827aa was **zero**; that is not evidence the lock code is absent.
Odin source 0x1b3d4 is numerically *below* function entry 0x1b6a8.
The first pass validated source membership in Ghidra's function-body
AddressSet. Confirm ownership and control flow from original instructions
before assuming this is a contiguous function.

**New follow-up tool:** tools/y2q_hxl1_rea_decision_path_review.py
(with tools/test_y2q_hxl1_rea_decision_path_review.py). It runs entirely
against saved Ghidra JSON and SHA256-checked HXL1 exports; does not launch
Ghidra, run native code, write firmware or communicate with the phone.
It re-authenticates all five search->xref->body links and extracts
bounded, line-numbered pseudocode context for actual inspection.

Run in WSL:

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_rea_decision_path_review
python3 tools/y2q_hxl1_rea_decision_path_review.py
cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/decision-path-review.md
~~~

After examining saved original pseudocode, expand the original runner
to additional searches and optional HighFunction dataflow if needed:

~~~bash
bash tools/run_y2q_hxl1_rea_security_audit.sh --seed-limit 6 --max-functions 24 --max-traces 2
~~~

Neither raw string hits nor isolated function pseudocode proves a
trusted-state transition, input reachability, bounds-check bypass,
a secure-world weakness or an installable custom image.

---


## 2026-10-11 — semantic corrections and focused REA high-p-code roots

The owner's 5/5-qualified `decision-path-review.md` provides
original Ghidra pseudocode for five authenticated function references.

**Important semantic corrections from code evidence:**

1. Odin `0x1ec00` prints `[OEM]Oem unlock value is %d`
   based on local_4c. This is a **value consumer/logging path**;
   the source of local_4c and its trusted state service are unverified.
2. Odin `0x1b6a8` tests `iVar9 == 0xc` and prints
   `Custom Binary... Blocked By OEM Lock` alongside error cases
   FRP, rollback, KG, CC Mode, and generic secure-check failures.
   This is evidence of an **error/status dispatcher**, not proof
   this function originally enforces the OEM lock. The observed
   xref 0x1b3d4 falls numerically **below** its 0x1b6a8 entry,
   despite membership in Ghidra's function-body ranges.
3. LinuxLoader `0x3f54` assigns the
   `Device is unlocked, Skipping boot verification` message
   only after calls to FUN_00039cdc and FUN_00004520.
   Their return conditions might govern logging, not
   verification itself; the actual authentication branch
   remains unverified.
4. LinuxLoader `0x5950` contains an indirect call using
   `param_1 + 0x40` and then sets
   `androidboot.vbmeta.device_state` to locked or unlocked
   according to the returned boolean. This is consistent
   with an AVB operation callback, but exact struct layout
   and the **origin** of the underlying protected device state
   must be established from this HXL1 binary.
5. LinuxLoader `0x2274` contains AVB error, rollback,
   partition, and unlock-count paths, but the report
   omitted much of the full function. Do not infer semantics
   from short text matches.

**New automation:** `tools/y2q_hxl1_rea_semantic_roots.py`
and `tools/run_y2q_hxl1_rea_semantic_roots.sh`. This runner:

- Re-checks the entire exact saved five-function REA search→xref→body
  chain against the pinned HXL1 SHA256 sources.
- Extracts carefully bounded **raw Ghidra pseudocode** context around
  specific input variables, callbacks and branch diagnostics.
- Defaults to only **two** expensive `trace-native-values`
  requests: Odin 0x1ec00 and LinuxLoader 0x5950.
- Can extend in a defined order to Odin 0x1b6a8,
  LinuxLoader 0x3f54 and LinuxLoader 0x2274 via `--count 5`.
- Preserves/reuses original REA evidence with strict operation,
  provider, query and artifact SHA256 checks; malformed prior
  evidence is never silently accepted.
- Does not interpret static graph edges as full authorization proof
  or execute a device exploit.

**Run host-only, on the existing WSL REA/Ghidra environment:**

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_rea_semantic_roots.sh
~~~

Or inspect the selected code contexts **without launching Ghidra**:

~~~bash
python3 tools/y2q_hxl1_rea_semantic_roots.py
cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/semantic-roots.md
~~~

After reviewing the first two bounded trace results, optionally run
`bash tools/run_y2q_hxl1_rea_semantic_roots.sh --count 5`.
Default per-request REA deadline is 240 seconds; a timed-out
request retains `.partial` and `.stderr.txt` for inspection.

The `semantic-roots.md` and `semantic-roots.json` reports
are saved within `rea-security-audit/`. Their trace metadata
includes original REA Evidence identifiers and collection sizes
but does not claim to resolve unknown indirect calls or
persistent secure-state sources.

**Next actual proof gate:** recover the producer of the Odin
error code (`piVar6[3]`) and the code initializing the
LinuxLoader callback at `param_1 + 0x40`. These are distinct
from logging the OEM lock state and logging AVB failures.

---


## October 11, 11:55 UTC — REA workflow provenance fix and saved trace recovery

The owner ran the first focused Ghidra semantic-trace command. The
underlying REA invocation exited without a process error, but our
old wrapper rejected the saved original output:

    [STOP] Ghidra provider / source / query provenance mismatch: .../Odin/trace-0x1ec00.json.partial

The retry correctly blocked on the pre-existing
`trace-0x1ec00.json.partial`. **Do not delete it.**

**Root cause in our code:** the general HXL1 evidence validator expects
provider `ghidra`, which is correct for primitive `search_strings`,
`xrefs`, and `analyze_function`. Upstream REA's
`trace-native-values` returns a composed workflow Evidence record with
provider `rea-workflow`, operation `trace_native_values`, and
the underlying Ghidra profile nested in
`analysis_profile.parameters.upstream_analysis_profile`. The
graph itself binds to a target via `target_sha256` and a seed
function via `seed`. This difference is also verified by REA's
`scripts/lib/native-value-e2e.mjs`.

Implemented `tools/y2q_hxl1_rea_trace_evidence.py` and updated
the existing REA runner to use a **separate trace-specific validator**
that checks the original HXL1 module SHA, procedure, REA workflow
identity, Ghidra upstream profile, exact root procedure, and bounded
graph fields. `--recover-partials` is an explicit opt-in that
validates the preserved .partial record and creates a second,
no-clobber hard link at the normal .json filename. It does not
overwrite or delete the .partial file or replay the completed REA
command. If validation fails, both original files remain untouched.

After a verified original trace is recovered, the script proceeds
to the second focus target and saves an updated report. Synthetic
validation and CI now cover workflow/primitive provider separation,
rejecting altered source, mismatched seed, bad upstream profile,
malformed partials, and safe no-clobber recovery.

**Owner command:**

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

bash tools/run_y2q_hxl1_rea_semantic_roots.sh --recover-partials

cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/semantic-roots.md
~~~

If this still stops, **preserve the original partial** and use this
read-only metadata projection to identify the remaining mismatch
without exposing the full high-p-code graph:

~~~bash
python3 - <<'PY'
import json
from pathlib import Path
p = Path.home() / "s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/Odin/trace-0x1ec00.json.partial"
d = json.loads(p.read_text())
g = d.get("normalized_result") or {}
ap = d.get("analysis_profile") or {}
print("operation:", d.get("operation"))
print("provider:", d.get("provider", {}).get("id"))
print("subject digest:", d.get("subject", {}).get("digest", {}).get("sha256"))
print("subject architecture:", d.get("subject", {}).get("architecture"))
print("query parameters:", d.get("parameters"))
print("workflow profile:", ap.get("provider", {}).get("id"))
print("upstream profile:", (ap.get("parameters") or {}).get("upstream_analysis_profile", {}).get("provider", {}).get("id"))
print("graph seed:", g.get("seed"))
print("graph source hash:", g.get("target_sha256"))
print("graph procedures:", [(x.get("address"), x.get("provider")) for x in g.get("procedures", [])[:6]])
print("graph truncated:", g.get("truncated"))
PY
~~~

Do not treat a recovered workflow trace as evidence that an indirect
unlock callback, protected state or a vulnerability has been established.

---


## October 11, 12:07 UTC — HXL1 original OEM and AVB high-p-code recovered

The owner executed the corrected semantic-root script with partial recovery.
BOTH original-source REA workflow traces were accepted and saved:

- Odin 0x1ec00: 947 returned graph nodes, 1164 edges, 16
  procedures, 90 unresolved observations.
- LinuxLoader 0x5950: 1000 returned graph nodes, 1228 edges,
  16 procedures, 181 unresolved observations.

These counts are **returned graph-page records**; the saved trace
also has total_nodes, total_edges, truncated and next_offset.
The LinuxLoader result reaches the default 1000-node output page
size, so establish pagination before making any completeness claims.

### Semantics from original Ghidra pseudocode

**Odin original SHA256**
09da14205be3e773f8b6ca9651fc9a1faabe871950b713ea79fc626e3c36de42,
function 0x1ec00:

- Calls FUN_00010e58 with literal persistent and receives a
  storage interface and geometry.
- Allocates a buffer using obtained size and reads data via
  the indirect pointer at local_40+0x18.
- Extracts **one byte from the end** of that buffer into local_4c
  with FUN_0000c11c, logs Oem unlock value and returns local_4c.
- The visible pseudocode does not show testing the indirect read
  operation's return status. This observation alone is NOT a
  demonstrated read failure or unlock bypass.
- The source's policy authority and integrity are unverified.
  This is better classified as OEM state *storage consumer*,
  not the original decision producer.

**LinuxLoader original SHA256**
5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003,
function 0x5950:

- Checks pointer field at param_1+0x40 and invokes it indirectly.
- Passes param_1 and the address of a one-byte local lock
  indicator to the callback.
- On a zero return, maps its output to locked/unlocked and
  appends androidboot.vbmeta.device_state. Nonzero returns enter
  a distinct error path.
- Exact function pointer initializer, secure origin, and
  how this callback relates to earlier verified-boot image
  acceptance are not yet established.

The raw saved workflow traces have original source identity
and Ghidra analysis-profile checks; valid Evidence does not
guarantee that individual indirect calls or secure-world
state origins are resolved.

### Offline saved-graph audit — new production tool

- tools/y2q_hxl1_rea_graph_forensics.py
- tools/test_y2q_hxl1_rea_graph_forensics.py

Before reading graphs, it validates the original HXL1 archive,
the exact source binaries and five search/xref/function proof
chains, plus BOTH saved REA workflow traces. It lists root
high-p-code call/call-indirect coordinates, static call edge
statuses, unresolved reasons, and **next_offset** page
availability. No REA or Ghidra binary is launched.

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/y2q_hxl1_rea_graph_forensics.py

cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/graph-forensics.md
~~~

The machine-readable companion is graph-forensics.json.
The exact saved raw trace paths remain Odin/trace-0x1ec00.json
and LinuxLoader/trace-0x5950.json.

**Next proof targets:** discover which firmware code selects,
authenticates and modifies the OEM-related persistent byte,
identify the storage interface contract and read-error behavior,
locate the constructor for the AVB callback pointer field, and
separate boot property reporting from trusted boot verification
and flashing authorization.

Do not patch the persistent partition, alter VaultKeeper/KG,
attempt cross-model firmware flashes or infer an unlock from
these static results.

---


## October 11, 12:31 UTC — actual graph coverage and paged CALLIND inventory

Owner-executed graph-forensics.md confirms pinned, saved traces:

| Component | Returned graph nodes | Graph total | REA decompilations | Next page | Graph status |
|---|---:|---:|---:|---|---|
| Original Odin 0x1ec00 | 947 | 947 | 16 | none | truncated = true, decompilation budget reached |
| Original LinuxLoader 0x5950 | 1000 | 1630 | 16 | 1000 | truncated/paged = true |

- Odin 0x1ec00 has 13 root calls, including exactly one
  recovered root indirect CALLIND at **0x1ec84**, with
  unresolved callee in the returned call relationships.
  The direct storage-lookup call at **0x1ec38** targets
  **0x10e58**; the original pseudocode passes literal
  persistent to this provider lookup and later obtains
  the OEM-related final byte using the indirect read.
  This does NOT establish storage authenticity or the
  producer of the status.
- Odin's 947/947 node result is *not complete semantics*:
  REA retained a truncated graph even though all retained
  nodes were emitted (90 unresolved observations and one
  decompilation-budget-reached diagnostic).
- LinuxLoader 0x5950 first page contains 135 root CALL/CALLIND
  operations: 132 direct + **three indirect**. Its original
  Ghidra trace page has 1630 total nodes / 1999 edges and
  1000 nodes / 1228 edges returned. Further 630 nodes
  remain. 181 unresolved observations include five
  unresolved call targets. The markdown inventory truncated
  to the first 48 root calls, so do not assume its omission
  of LinuxLoader CALLIND addresses means they are absent.
- "Target not on page" for static CALL edges frequently
  refers to a **procedure address** or a different graph page,
  not necessarily a missing implementation or unsafe jump.

**New bounded, cache-reusing workflow:**

- tools/y2q_hxl1_rea_indirect_pages.py
- tools/test_y2q_hxl1_rea_indirect_pages.py
- tools/run_y2q_hxl1_rea_indirect_pages.sh

The script SHA-attests the original binaries and five proved
search/xref/function chains, then verifies existing workflow Evidence
and requests *only* the next LinuxLoader graph page (offset 1000,
limit 1000) in --execute mode; do not rerun Odin. The page-specific
result is saved separately as
rea-security-audit/LinuxLoader/trace-0x5950-offset1000-limit1000.json.
Saved original files are never replaced. The new validator
checks exact requested offset/limit in REA parameters and graph
pagination before promoting the result. Merging checks total nodes,
total edges, decompilation counts, procedure list, unresolved records,
non-overlapping node IDs, and original SHA256.

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_rea_indirect_pages.sh --recover-partials
~~~

Read the output:

~~~bash
cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/indirect-call-pages.md
~~~

Alternatively run the Python command without --execute to get a
PLAN report and use any already-verified cached page without launching
Ghidra. The saved report inventories all root CALLIND sites and
distinguishes graph page coverage from the Ghidra work budget.

**Unresolved:** exact Odin storage read target and error handling,
LinuxLoader callback initializer / data origin, the separate source
of Odin OEM authorization codes and secure-world policy enforcement.
No unlock, arbitrary firmware execution or vulnerability demonstrated.

---


## October 11, 12:46 UTC — full saved graph pages and exact native callsite investigations

The owner executed the original-REA page collector and obtained:

- Odin function 0x1ec00: 947/947 returned nodes, original
  single **CALLIND at 0x1ec84**, static target not recovered.
  Decompilation budget at 16 reached; 90 unresolved diagnostics.
- LinuxLoader function 0x5950: 1630/1630 returned nodes
  across two original-source-attested pages, **CALLIND at
  0x5dc4, 0x5ea4, and 0x6020** (all Ghidra member blocks).
  Decompilation budget at 16 reached; 181 unresolved diagnostics.
- Second LinuxLoader page Evidence ID:
  ev_96f94aadb14d6b1e0b3393fba0d2162cc7d2416361d7ef6afe5693997bc55a1e.
  Neither trace has missing *retained pages*, but both have
  incomplete *analysis coverage*. These are different gaps.

The exact identification of the LinuxLoader native instruction that
calls read_is_device_unlocked remains **OPEN**. Three indirect calls
exist; it is unsupported to call any one the device-state callback
based on a location alone.

**Automated next stage:** inspect decoded native instruction and
provider-resolved static call targets of the four Ghidra-member
CALLIND sites, and obtain the first original Ghidra function dossier
for Odin's direct persistent-storage provider lookup **0x10e58**.

- tools/y2q_hxl1_rea_callsite_attribution.py
- tools/test_y2q_hxl1_rea_callsite_attribution.py
- tools/run_y2q_hxl1_rea_callsite_attribution.sh

The script verifies the **original five HXL1 search/xref/function
chains**, component hashes and the two complete saved graph pages.
It admits exactly the four owner-proven original CALLIND instruction
coordinates; it does not seek undefined offsets from heuristic
strings. It runs up to nine NEW bounded direct-Ghidra queries,
each cached in separate SHA-validated saved Evidence. The static
provider target resolution operation is resolve_native_call_targets,
and the native instruction inspection is inspect_native_instruction.
Both are distinct from REA workflow traces, and reuse the validated
Ghidra primitive Evidence schema. Missing or ambiguous callback
targets remain UNKNOWN.

Run on original owner WSL machine:

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_rea_callsite_attribution.sh --recover-partials
cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/callsite-attribution.md
~~~

Read-only plan mode:

~~~bash
python3 tools/y2q_hxl1_rea_callsite_attribution.py
~~~

Original Evidence will be saved under rea-security-audit/Odin
and rea-security-audit/LinuxLoader, respectively as
instruction-0x*.json, resolve-call-0x*.json and
function-0x10e58.json. The report is callsite-attribution.md/json.

The follow-up questions remain: recover the storage-interface
read target and status handling, locate the LinuxLoader
param_1+0x40 pointer initializer, identify the separate Odin
security-result producer, and establish actual policy authority.
A resolved static callee would still not demonstrate exploitability,
an authorization bypass or an unlocked SM-G986U1.

---


## October 11, 13:14 UTC — original Ghidra indirect-call targets unresolved

The owner executed all nine new bounded original HXL1 REA/Ghidra
queries (four native instruction inspections, four direct static
call-target resolutions, one original Odin function dossier).
The completed report was callsite-attribution.md.

The exact original-source ARM64 instruction observations:

| Module/owning function | Native CALLIND site | Original instruction | Ghidra static resolver |
|---|---|---|---|
| Odin 0x1ec00 | 0x1ec84 | blr x9 | unresolved, no candidate |
| LinuxLoader 0x5950 | 0x5dc4 | blr x8 | unresolved, no candidate |
| LinuxLoader 0x5950 | 0x5ea4 | blr x8 | unresolved, no candidate |
| LinuxLoader 0x5950 | 0x6020 | blr x8 | unresolved, no candidate |

The four unresolved static destinations are **not** vulnerabilities
or evidence that the corresponding calls cannot execute at runtime.
They require function-pointer load/initialization research.

Odin storage-provider helper **0x10e58** is now an original
SHA256-verified Ghidra function dossier, with 58 decompiled lines.
The old lexical-only report displayed only lines 44–56:
a partition-enumeration error message, Partition not found,
and an error return. Its remaining source-backed code was saved
but not visible in the truncated report. The complete function
must be read before claiming interface selection or authorization.

### No-new-REA follow-up: backward value slices

New repository scripts:

- tools/y2q_hxl1_rea_indirect_value_slices.py
- tools/test_y2q_hxl1_rea_indirect_value_slices.py

They reconstruct four bounded backward p-code def-use slices
starting with the **CALLIND target operand at input index 0**.
A parameter binding or other call argument is *not* a proven
target-definition edge. The slicing is capped at depth 7 and
72 operations per site. Ghidra LOAD and STORE do not convey
authoritative object aliasing, authentication, the initializer
of an AVB callback, or protected state by themselves.

Before analysis, the script verifies:

1. Original SHA256-pinned HXL1 BL component inventory and five
   independently proven original Ghidra string→xref→function chains.
2. Both saved REA workflow graphs and LinuxLoader page 2,
   including exact query offset, nonoverlapping retained node IDs
   and graph page consistency.
3. Four owner-observed source-attested Ghidra native CALLIND
   instruction and unresolved static-target Evidence records.
4. Odin's independently verified 0x10e58 Ghidra function dossier,
   and original LinuxLoader 0x5950/0x2274 dossiers.

The report includes line-numbered **full original 0x10e58
pseudocode** (58 lines), bounded 0x2274 AVB callback-initializer
search context, and 0x5950 callback-use context. No new REA,
Ghidra, firmware, Odin, ADB or handset calls are made.

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/y2q_hxl1_rea_indirect_value_slices.py

cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/indirect-value-slices.md
~~~

Machine-readable companion:
rea-security-audit/indirect-value-slices.json.

**Interpretation gate:** identify actual p-code LOAD/PTRADD
origin of each BLR target and distinguish the active device-state
callback from the other AVB indirect calls using code evidence.
If the SSA backward chains terminate at LOADs, the next stage
is callback interface assignment/initializer xrefs, not a claim
of a missing validation step.

**Remaining security gate:** distinguish partition-stored
OEM diagnostic byte from authoritative unlock/flash policy
as decided by Samsung/Qualcomm secure-world state. No
bootloader unlock or vulnerability has been demonstrated.

---


## October 11, 13:22 UTC — HXL1 AVB indirect callback field identity

The owner ran original-HXL1 saved Ghidra/REA backward p-code
slices, with zero new REA/Ghidra commands.

**Verified original LinuxLoader 0x5950 callsite values:**

| CALLIND native site | BLR register | Exact p-code LOAD | Base and displacement |
|---|---|---|---|
| 0x5dc4 | x8 | 0x5db4 | param_1 + 0x40 |
| 0x5ea4 | x8 | 0x5e90 | param_1 + 0x48 |
| 0x6020 | x8 | 0x600c | param_1 + 0x48 |

All three are Ghidra-live CALLIND operations whose p-code target
input[0] resolves through a single LOAD, CAST and INT_ADD rooted
in function parameter 0. The three **concrete destinations remain
unresolved** because no pointer-table initialization or memory alias
target has been established.

The strongest read_is_device_unlocked callback **callsite**
is **0x5dc4**, because its +0x40 field invocation in original
0x5950 pseudocode writes an output boolean, tests callback status,
then constructs androidboot.vbmeta.device_state as locked/unlocked.
The two +0x48 sites reuse a **different** pointer field and
should not be conflated with this lock-state call.

The Android Open Source Project libavb avb_ops.h explicitly
defines read_is_device_unlocked and get_unique_guid_for_partition
as **adjacent struct fields**, but exact numeric offsets differ
across versions. The older interface with no extra fields
places these at +0x38 / +0x40 on AArch64, whereas later revisions
with cert_ops and get_preloaded_partition fields move them to
+0x48 / +0x50. Samsung HXL1's observed +0x40 / +0x48 **must not**
be equated to either unverified upstream ABI version.
AOSP source comparisons:
https://android.googlesource.com/platform/external/avb/+/f242f0edbe0dd40f77ea04a05dd80f99b370996b/libavb/avb_ops.h
https://android.googlesource.com/platform/external/avb/+/master/libavb/avb_ops.h

**Odin original 0x1ec84** resolves as LOAD from a per-partition
interface pointer at local_40+0x18. The initial pointer emerges
from the original partition discovery helper 0x10e58, which
iterates registered partition handles, obtains a protocol
interface from DAT_0028cfa8+0x98, compares the partition name,
and returns interface/handle pointers on a match. The p-code
chain is capped at depth 7 and retains memory alias limitations.
Neither a trusted OEM value producer nor storage authenticated
integrity is proved.

**LinuxLoader original caller 0x2274** invokes 0x5950 using
pbVar20 as argument 0, observed at pseudocode line 437. The
object initializer assigning +0x40/+0x48 to this object is
still unknown. We cannot infer that pbVar20 is trusted, or that
the Android boot-state property controls the separate signature
and flashing authorization gates.

New purely offline original-evidence analyzer:
tools/y2q_hxl1_avb_callback_fields.py
with synthetic tests tools/test_y2q_hxl1_avb_callback_fields.py.

This script first re-validates the original SHA-pinned
five Ghidra string/xref/function chains, four native BLR
sites, source-bound p-code pages, and full 0x2274 dossier.
It then:
- fails closed unless observed target ADD displacements are
  +0x40, +0x48, +0x48 via original parameter 0;
- extracts all original 0x2274 pseudocode lines mentioning
  pbVar20, assignments to that variable, and its call
  to FUN_00005950;
- compares two AOSP ABI variants *without* asserting
  a Samsung type layout;
- records the missing initializer, trusted lock-state source,
  and image authorization as **unproved**.

Owner-run command, no new REA or Ghidra required:

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 tools/y2q_hxl1_avb_callback_fields.py
cat ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/avb-callback-fields.md
~~~

No device state changes, firmware modifications, secure-storage
writes, exploit demonstrations or unlocked bootloader occurred.

---


## October 11, 13:38 UTC — exact original AVB object producer located

Owner ran the original-source callback field attribution tool. All
three indirect call pointer-field offsets and full 1173-line 0x2274
Ghidra caller context were successfully verified offline:

- LinuxLoader 0x5950 CALLIND 0x5dc4 reads AvbOps-like
  first-parameter field +0x40; associated decompiled callback
  writes the lock-state output used for
  androidboot.vbmeta.device_state.
- LinuxLoader 0x5950 CALLIND 0x5ea4 and 0x6020 both read
  field +0x48; neither is a proven lock-state implementation.
- Ghidra reports 0x2274 local pbVar20 uses on lines
  24, 303, 311, 313, 343, 344, 437, 636, 658, 738.
  The **owner-proven constructor/result assignment** is at
  pseudocode line 343:

    pbVar20 = (byte *)FUN_0000b7a4(pcVar19);

  The same Ghidra variable is then passed as argument 0 at
  pseudocode line 437:

    uVar9 = FUN_00005950(pbVar20,pcVar29,pcVar34);

  Both lines are in the original 0x2274 Ghidra function; this
  establishes a concrete **constructor or allocation-helper
  candidate** at 0xb7a4. Formal control-flow domination,
  callback assignments or the concrete type of the returned
  object remain to be verified.
- Other assignments at lines 303, 636 and 658 set the
  decompiler variable pbVar20 to NULL or param_1.
  Lines 636/658 appear in cleanup/error paths; **do not**
  conclude param_1 is a second valid AvbOps constructor
  from these observations.
- Original 0x2274 code includes the error
  "Failed to allocate AvbOps", and a cleanup call
  FUN_0000b858(pbVar20), which independently strengthens
  the allocation / lifetime-management interpretation but
  does not prove callback-table field writes or lock policy.

### Targeted new single-function static Ghidra probe

- tools/y2q_hxl1_rea_avb_constructor.py
- tools/test_y2q_hxl1_rea_avb_constructor.py
- tools/run_y2q_hxl1_rea_avb_constructor.sh

The tool revalidates the owner-pinned HXL1 archive and
LinuxLoader source hash, original five Ghidra
search/xref/function chains, existing Ghidra BLR
instruction Evidence, saved graph pagination, and
the original 0x2274 caller. It accepts exactly one
new source-bound Ghidra function query:

    rea function LinuxLoader-HXL1.efi 0xb7a4 --provider ghidra --json

Actual binary path is taken from the verified owner hotspot
inventory, not inferred from this documentation. Output is
saved only to the separate original-evidence file
rea-security-audit/LinuxLoader/function-0xb7a4.json.
Pre-existing original files are never modified.

It displays bounded constructor pseudocode including
initial lines, candidate callback field offsets
+0x40/+0x48, lexical memory assignments, and
direct callee references as an investigation queue.
**Pseudocode text matching a memory assignment does
not itself prove target pointer aliasing, a reachable
write or secure authorization.**

Owner-run WSL command:

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_rea_avb_constructor.sh
~~~

Report:

    ~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit/avb-constructor.md

This is a host-only exact HXL1 static analysis operation,
not a firmware patch, phone-side operation or unlock.
The immediate research goal is to determine if 0xb7a4
populates both callback table fields locally or
delegates to another original static function.

---


## October 11, 13:46 UTC — original HXL1 AVB callback slots assigned

Owner ran exact original LinuxLoader Ghidra function investigation of
0xb7a4 from the saved AvbOps caller source 0x2274.

**Source-attested original Ghidra function Evidence:**
ev_4168cd8e93bf7d4946c55989205b9bc7d626b4f7b4cdb919b0c05c7e5ec09cb1
for the LinuxLoader-HXL1.efi SHA256
5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003.

Exact Ghidra decompilation of 30-line original 0xb7a4
shows a **0x60-byte allocation**, user-data capture, and
local initialization of an AvbOps-like callback table:

    puVar2 = (undefined8 *)FUN_00008cd4(0x60);
    ...
    *puVar2 = param_1;                // object +0x00
    puVar2[3] = FUN_0000a598;         // +0x18
    puVar2[4] = &LAB_0000ad44;       // +0x20
    puVar2[0xb] = &LAB_0000af2c;     // +0x58
    puVar2[5] = FUN_0000ad4c;        // +0x28
    puVar2[6] = FUN_0000b150;        // +0x30
    puVar2[7] = FUN_0000b1e0;        // +0x38
    puVar2[8] = FUN_0000b2bc;        // +0x40
    puVar2[9] = &LAB_0000b30c;       // +0x48
    puVar2[10] = FUN_0000b6b4;       // +0x50

Note: The original function decompiler reports these assignments,
not a separately proven native STORE/data alias, immutable callback
table, runtime invocation or trusted secure state source. Nor does
the report prove the semantics of every index or how slots +0x08/
+0x10 are initialized.

**Correlation with prior source-attested Ghidra p-code:**

- At original LinuxLoader 0x5950 CALLIND **0x5dc4** (BLR x8),
  the function pointer is a LOAD from **param_1+0x40**.
  Constructor's **puVar2[8]** selects candidate
  **FUN_0000b2bc**. This is now a *specific static implementation
  candidate*, not an unresolved anonymous field.
- At original CALLIND 0x5ea4 and 0x6020, both LOAD
  **param_1+0x48**; constructor's **puVar2[9]**
  assigns **&LAB_0000b30c**. The Ghidra **LAB_** name
  does NOT prove that 0xb30c is a function entry.
- At original 0x2274 line 343, pbVar20 is assigned
  FUN_0000b7a4(pcVar19) and passed to the original
  AVB consumer 0x5950 at line 437.

### Two original-source, bounded Ghidra next probes

Files committed:
- tools/y2q_hxl1_rea_avb_callback_implementations.py
- tools/test_y2q_hxl1_rea_avb_callback_implementations.py
- tools/run_y2q_hxl1_rea_avb_callback_implementations.sh

Before collecting any Evidence, tool validates archive and
firmware SHA256, original five reference proof chains,
the complete two-page REA value graphs, the source-attested
BLR observations and exact +0x40/+0x48 LOAD operands.
It then **fails closed unless** the original 0xb7a4
Ghidra dossier matches one 0x60-byte allocation,
user-data assignment and exactly one each of
puVar2[8]=FUN_0000b2bc and puVar2[9]=&LAB_0000b30c.

Owner WSL command:

~~~bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_rea_avb_callback_implementations.sh
~~~

The only two new static host-side queries are:
1. **REA function 0xb2bc**, to read the original full lock-state
   callback candidate's implementation, error paths and call sources.
2. **REA inspect-native-instruction 0xb30c**, to check if
   LAB_0000b30c is a valid code instruction and record its
   owning Ghidra procedure, without inventing a function entry.

The output is avb-callback-implementations.md/json under
~/s20-artifacts/hxl1-research/bootloader-unlock/rea-security-audit.
New Evidence is preserved separately under
LinuxLoader/function-0xb2bc.json and
LinuxLoader/instruction-0xb30c.json. No original saved
Evidence is overwritten.

**Next gate after owner run:** determine 0xb2bc's actual lock
state source and whether any error status is fail-closed.
Do not confuse producing androidboot.vbmeta.device_state
with controlling the independent verified-boot signature or
Odin flashing authorization checks. No unlock or exploit
is demonstrated.

---

## Reverse-engineering decision gates

1. **Image provenance:** independently hash and identify both firmware archives;
   record region, AP/BL version, anti-rollback / binary revision and exact package.
2. **Relevant component identification:** inspect nested ABL UEFI/FFS modules;
   don't mistake all functions in the outer ELF for the security-policy implementation.
3. **Unlock authorization call graph:** from OEM lock/unlock UI and Download Mode
   callbacks, locate state consumers/producers and conditional paths in the
   *factory* G986U1 code. Authenticate symbols by disassembly and xrefs.
4. **Secure-world boundary:** identify calls to VaultKeeper / relevant TEE services
   and determine which state is normal-world vs authenticated/secure storage.
   An Android property is not evidence that protected state can be rewritten.
5. **Cross-model semantic comparison:** line up corresponding G986U1/G9860
   module GUIDs, sizes and entry points, then compare specific call graphs and
   branch semantics; string differences alone do not prove eligibility logic.
6. **Flash and boot verification:** separately map Odin/Download Mode authorization,
   AVB/KVB key trust and rollback checks; writing bytes is not equivalent to
   booting unsigned code. EDL does not imply an available authorized Firehose.
7. **Hardware testing and recovery:** only after provenance and a reversible
   authorized test are established, document recovery, backup and Knox/wipe
   implications. Do not try cross-model flashing or arbitrary patched ABL.

## Targeted next analysis questions for Ghidra / REA

- Which ABL module or firmware service supplies the immutable-looking
  user-facing lock state, and where is the decision consumed?
- Does G986U1 contain any genuine OEM unlock state transition implementation?
- Does G9860 use the same method with a different configuration/identity
  input, or a materially different code path?
- What is the earliest **trusted** component that validates ABL and the later
  Android boot image, and how does it obtain acceptable key/revision policy?
- Which Download Mode service authorizes custom-image writes, and which
  separate service verifies execution on next boot?

### Evidence grading

- `CONFIRMED`: reproducible original-binary bytes/instructions with hash and caller.
- `CANDIDATE`: string, symbol, format or structural analogy needing code validation.
- `UNVERIFIED`: device decision, secure-state read, matching comparator build, unlock.
- `NOT_AVAILABLE`: source bytes or runtime state cannot be accessed currently.

## Security and validation background

- Samsung Knox Trusted Boot: https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/system-security/trusted-boot/
- Samsung Knox hardware/root-of-trust and rollback fuses: https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/system-security/hw-backed-security/

**Go/no-go as of this file:** static comparison infrastructure is implemented;
exact HXL1 original bytes are locally owned, but comparator binary not yet
supplied, semantic unlock call graph unverified, hardware lock still intact.
Neither a KernelSU prerequisite nor a verified software-only unlock is established.
