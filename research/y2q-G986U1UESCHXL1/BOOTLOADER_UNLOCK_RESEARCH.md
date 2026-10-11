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
