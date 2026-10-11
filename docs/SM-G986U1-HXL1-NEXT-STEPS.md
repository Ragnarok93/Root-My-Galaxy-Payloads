# SM-G986U1 HXL1 — current porting execution guide

## Current priority — validated REA DTB/DTBO index xrefs (October 11, 2026)

**Owner hardware / stock REA evidence now confirmed:**

| Original index string (Ghidra PE address) | Exact xref source | REA evidence ID |
|---|---|---|
| `androidboot.dtb_idx=` (`0xbfd99`) | `0x2c350` | `ev_b31e5021edd1b1d5db9ff58336bb5e0f0abc3ff1d8e2189e6ce93363a5c796db` |
| `androidboot.dtbo_idx=` (`0xbfd82`) | `0x2c308` | `ev_14dae88115f0805e73bc32804d89232d6212f4d3e65c777c335cd9ff09557a1b` |

Both responses were checked with the existing, original-SHA-pinned
`y2q_linuxloader_rea_stage4_xrefs.parse_xrefs`. Exactly one
original **static** reference was verified per literal string.
The instruction sources are `0x48` (72 decimal) bytes apart,
but **do not call them the same function before Ghidra function
body validation**.

The retained local evidence folder is
`~/s20-artifacts/hxl1-research/abl-linuxloader/rea-dt-index-LBaPQ6`.
The exact `LinuxLoader-HXL1.efi` digest remains
`5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`.
No original DTBO image was found among the filenames searched
under `~/s20-artifacts`. Two ADB reports reported
`ro.boot.dtb_idx=0` and `ro.boot.dtbo_idx=2`, but
neither a running DTB hash nor overlay entry table was obtained.
Index-domain-to-offline-tree mapping is not proved.

### Immediate next REA step: only two owning-function dossiers

Run the **existing REA fork** on the **two already-verified xref
source instruction addresses**, with the **existing**
`tools/y2q_linuxloader_rea_stage4_functions.py::validated`
function to authenticate the returned original PE, Ghidra operation,
exact requested address and containing function body. Don't re-run
the xrefs or run a new whole-image scan.

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

bash -euo pipefail <<'BASH'
OUT="$HOME/s20-artifacts/hxl1-research/abl-linuxloader"
RUN="$OUT/rea-dt-index-LBaPQ6"
EFI="$OUT/LinuxLoader-HXL1.efi"
REA="$HOME/src/rea/scripts/rea.mjs"
PIN=5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003

test -d "$RUN" && test -f "$EFI" && test ! -L "$EFI" && test -f "$REA"
printf '%s  %s\n' "$PIN" "$EFI" | sha256sum -c

if test -s "$HOME/.nvm/nvm.sh"; then
  export NVM_DIR="$HOME/.nvm"
  . "$NVM_DIR/nvm.sh"
  nvm use 24 >/dev/null
fi
if test -s "$OUT/rea-ghidra-env.sh"; then
  . "$OUT/rea-ghidra-env.sh"
fi

# Keep the two source xref reports: read them, do NOT repeat the queries.
for label in dtb-index dtbo-index; do
  test -s "$RUN/$label-xrefs.json"
done

for spec in "dtb-index 0x2c350" "dtbo-index 0x2c308"; do
  read -r label address <<< "$spec"
  target="$RUN/rea-stage4-function-$label.json"
  test ! -e "$target" || {
    echo "[STOP] Existing function report: $target (no overwrites)"
    exit 2
  }
  echo "[REA FUNCTION] $label $address"
  node "$REA" function "$EFI" "$address" --provider ghidra --json \
    > "$target"
done

python3 - "$RUN" <<'PY'
import sys, re
from pathlib import Path
from tools.y2q_linuxloader_rea_stage4_xrefs import parse_xrefs
from tools.y2q_linuxloader_rea_stage4_functions import validated

folder=Path(sys.argv[1])
records={}
for label,string_addr,source in (
    ("dtb-index","0xbfd99","0x2c350"),
    ("dtbo-index","0xbfd82","0x2c308"),
):
    references=parse_xrefs(folder/(label+"-xrefs.json"),string_addr)
    assert references["sourceAddresses"]==[source], (
        label, references["sourceAddresses"])
    result=validated(folder,label,source)
    records[label]=result
    print("[ORIGINAL GHIDRA]",label,"xref:",source)
    print("  owning function:",result["entry"],result["name"])
    print("  p-code available:",result["pcodeAvailable"],
          "truncated:",result["pcodeTruncated"])
    print("  evidence:",result["evidenceId"])
    lines=result["pseudocode"].splitlines()
    matches=[n for n,l in enumerate(lines) if
             re.search(r"(?i)(dtb_idx|dtbo_idx|androidboot|cmdline)",l)]
    shown=set()
    if not matches:
        print("  No relevant literal in pseudocode: first 35 lines only")
        matches=list(range(min(35,len(lines))))
    for n in matches[:12]:
        for j in range(max(0,n-4),min(len(lines),n+6)):
            if j not in shown:
                print(f"    {j+1}: {lines[j][:250]}")
                shown.add(j)
print("[SHARED OWNING FUNCTION]",
      records["dtb-index"]["entry"]==records["dtbo-index"]["entry"])
print("[EVIDENCE]",folder)
print("[LIMIT] Static formatting path, not verified boot-time index mapping")
PY
BASH
```

If both xrefs share one function, inspect that **one** original
function's relevant CFG/HighFunction p-code before invoking
`trace-native-values`. If they differ, determine their caller
relationship first. In either case follow the index value
source rather than a raw string-address pointer, and preserve
unknown indirect calls, memory aliases, runtime DTB selection,
UEFI base/KASLR and unsigned kernel module loading.

REA CLI contracts:
[CLI](https://github.com/Ragnarok93/rea/blob/main/docs/cli.md),
[Ghidra function and p-code](https://github.com/Ragnarok93/rea/blob/main/docs/ghidra-provider.md),
[bounded tracing](https://github.com/Ragnarok93/rea/blob/main/docs/native-investigation.md).

**No exploitation, root, runtime physical load, working KernelSU
or support-feed promotion is established**. Stages 3–5 remain
partial/open; 7–8 blocked. No device modification.


---

**Status: RESEARCH ONLY. No HXL1 root, exploitable runtime primitive, KernelSU load, installable profile or support-feed entry has been demonstrated.**

This is the **current operational entry point** for [`docs/PORTING.md`](PORTING.md)
applied to **SM-G986U1 / G986U1UESCHXL1 / y2q / Android 13 /
4.19.113-27095354**. The extensive
[device adaptation](SM-G986U1-G986U1UESCHXL1.md) and
[historical evidence log](../research/y2q-G986U1UESCHXL1/ROOT_PAYLOAD_RESEARCH.md)
remain the evidence trail, **not a sequence of commands to rerun**.
For Samsung KernelSU source and versioned artifacts consult
[`kernelsu/README.md`](../kernelsu/README.md). Never transplant
the S24 FE/S24 Ultra's Linux 6.1 values into HXL1's Linux 4.19.

## Exact gate state, as of October 11, 2026

| PORTING.md | State | Verified already | What *actually* remains |
|---|---|---|---|
| 1. Exact firmware | COMPLETE | Owner ADB / Shizuku model, fingerprint, HXL1 kernel, locked bootloader, SELinux enforcing, shell UID 2000 | Recheck only after a firmware change |
| 2. Extract stock inputs | COMPLETE (offline originals) | Hash-pinned boot v2, ARM64 kernel Image, config, vendor source from 11 overlays, matching BL archive and parsed DTB streams | Only running-kernel/selected DTB identity is unproven; do not restart downloads |
| 3. Kernel symbols/layouts | PARTIAL, **active gate** | Recovered original Image ELF/NM, source fix review, 11 raw Image code windows; two Clang18 rtmutex/futex objects and internally consistent DWARF | Prove source-to-factory-instruction semantics and **independent factory-compiled** layouts; no original BTF/DWARF established |
| 4. Physical BL handoff | OPEN | Original ABL/XBL/XBL_CONFIG and Android boot-v2 fields; DTB candidates; some original EFI static flow | *Actually selected* boot chain/device tree and physical Linux load remain unknown |
| 5. Per-boot runtime metadata | OPEN | Device-specific non-root identity and some tracefs metadata | Device runtime slide, trace/worker and physical fingerprint details, where accessible; never import another device's constants |
| 6. Native target | OPEN | Firmware-locked inert Android diagnostic | Runnable HXL1 privilege chain, not just source code or Clang18 objects |
| 7. KernelSU | BLOCKED | Stock CONFIG_MODULE_SIG_FORCE=y, CONFIG_KPROBES=n, Samsung RKP/KDP/DEFEX | Proven code loading, kernel 4.19 hooking and OEM-specific compatibility |
| 8. App/feed | BLOCKED | Research-only identity gating | Actual hardware-verified secure integration; no HXL1 in `support/targets-v3.json` |
| 9. Recovery/release | DEFERRED | Original evidence retained | Repeatable owned-device recovery/testing before any risky execution |

**Treat the evidence source as immutable.** Original extracted
`~/s20-artifacts/kernel.bin` SHA256:
`ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.
The Clang18 two-object agreement is **experimental only**, *not*
a Samsung factory Clang10 ABI match. Even factory code-window hashes do
not themselves provide verified member offsets or runtime addresses.

## Do this next — one gate at a time

### A. Reconcile the documented nine-stage gates (run now)

In WSL2:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 -m unittest -q tools/test_y2q_porting_readiness.py
python3 tools/y2q_porting_readiness.py \
  --output "$HOME/s20-artifacts/hxl1-research/port-readiness-20261011.json"

cat "$HOME/s20-artifacts/hxl1-research/port-readiness-20261011.md"
```

**Pass:** tests pass; Stage 1 and Stage 2 COMPLETE; Stage 3
PARTIAL; Stage 4–5 OPEN; Stage 6 OPEN; Stage 7–8 BLOCKED;
Stage 9 DEFERRED; `payloadPortCompleted=false`.
If anything disagrees, investigate the *specific input*; **do not
mark a gate complete by editing the evidence manifest alone**. The
readiness utility is the status authority for the nine gates, not
how many auxiliary analyzers or Clang18 tests have passed.

### B. Review original compiled kernel vs original source (next active step)

Use the **already implemented** code-review tool, not another kernel
build, BTF extractor or new symbolic-analysis framework:

```bash
bash tools/run_y2q_hxl1_stock_rtmutex_source_code_review.sh
```

**Input:** the already created original
`~/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-code-windows-v2.json`,
hash-pinned original `kernel.bin`, `vmlinux-stock.nm`,
and original Samsung `kernel/locking/rtmutex.c` and
`kernel/futex.c`.

**Pass:** all 11 original code windows independently match actual
Image instruction words; original source hashes match; source
functions `remove_waiter`, `rt_mutex_start_proxy_lock` and
`futex_lock_pi` can be reviewed side-by-side. Save the write-once
`hxl1-stock-rtmutex-source-code-01.md`/JSON (or the next unused numbered
pair: `-02`, `-03`, etc. if a prior run already produced files).
The runner preserves existing reports rather than overwriting them.
An explicit `--out /path/to/report.json` is never auto-renamed and will
fail with the occupied filename if either JSON or Markdown exists.
**No source-level
operation has yet been proven to map to a specific factory structure
offset by this name-based report.** Review it before any new tools
or code are justified.

**Actual owner result (October 11, 2026):** The readiness tool passed
9/9 checks and classified stages 1–2 COMPLETE, 3 PARTIAL, 4–6 OPEN,
7–8 BLOCKED and 9 DEFERRED. The 11 original full-symbol-bounded
windows passed the source review (67/67 local tests); three
name-associated source definitions were found at original
`rtmutex.c:1068–1119`, `rtmutex.c:1797–1810`, and
`futex.c:2817–2998`. Their 192-byte code limits truncate
`remove_waiter` and `futex_lock_pi`.

The first report was already present, so the tool successfully wrote
`hxl1-stock-rtmutex-source-code-02.md` and JSON, but **then**
crashed while printing the terminal review because a summary-loop
variable overwrote the parsed `--show-review` arguments. The CLI
shadowing has been corrected with regression tests. **The existing
`-02.md` report is valid and need not be regenerated.** Use:

```bash
cat "$HOME/s20-artifacts/hxl1-research/hxl1-stock-rtmutex-source-code-02.md"
```

Share this already-generated report for review before taking further
action; do not create a third redundant report merely for terminal
printing. Neither the report nor its disassembly proves factory member
offsets, exact full function semantics, boot relocation or root.

### C. Samsung FUS metadata check — optional, *not a new prerequisite*

The reference [`PORTING.md`](PORTING.md) uses
[`samloader-rs`](https://github.com/topjohnwu/samloader-rs)
to retrieve the **S721N/LUC** sample firmware. Those model/region and
four-part version values **must not** be copied for the S20+.

The original HXL1 kernel/boot/BL is already present and hash verified.
`samloader-rs` can query *currently available* official Samsung FUS
metadata, but `check-update --all` may not return an archived
HXL1 version, and a different currently offered build must not
replace the audited source or change the profile identity.

If `samloader` is already installed, **first determine the owner's
actual active sales/CSC code** from existing device metadata, then run:

```bash
samloader --version
samloader check-update --model SM-G986U1 --region ACTUAL_CSC --all --verbose
```

Replace `ACTUAL_CSC` **only** with independently observed CSC/sales
region (e.g. do not assume `XAA` simply because the model ends
in `U1`). This is a network firmware listing only. Do **not** run
`samloader download`, `flash`, `detect`, `reboot-download`,
or PIT/partition commands as part of this audit.
If the binary is absent or FUS omits HXL1, record
`FUS_HISTORICAL_LOOKUP_UNAVAILABLE` and continue:
existing original hash provenance remains intact.

### D. After B passes: identify the *specific* unresolved factory gate

Use the **already installed** tools for the actual gap:

- `llvm-objdump` / `aarch64-linux-gnu-objdump`, `llvm-nm`,
  recovered original `vmlinux-stock.elf` and source for
  static source-to-code examination. Use Ghidra *only if* bounded
  CLI disassembly is ambiguous and an address/branch-flow question
  requires it.
- `vmlinux-to-elf` has **already** been used. Its symbol recovery
  is not factory DWARF. `pahole` worked for our **Clang18-built
  objects**; their fields are not original layout evidence.
- Original `kernel.bin` had **no valid bounded raw BTF candidate**
  in the existing scan, and the reconstructed ELF exposes no
  original verified DWARF/BTF. `bpftool` is useful only if an
  **actual original BTF blob** is found; installing it alone cannot
  create original type information.
- Use existing HXL1 ABL/XBL, boot header and FDT reports for Stage 4,
  **after defining a specific physical-handoff proof question**.
  Static EFI RAM-region fields are not kernel load addresses.
- Use existing **read-only ADB/Shizuku** capability/identity probes
  for Stage 5 only when a concrete runtime question remains. Clearly
  distinguish `uid=2000` shell privileges from an ordinary app.
  Do not perform unsafe futex stress, kernel writes, or blind
  memory probing.

### E. Explicit stop/go policy

**Stop:** If factory field association or the kernel-loading chain
cannot be independently authenticated, record `UNVERIFIED`.
No more full Samsung kernel Image compilations, repeat Clang18 layout
extractions, speculative offset guessing, or redundant report
generators solely to inflate the completed-test count.

**Go:** Native device-specific implementation/KernelSU/app work can
only proceed after independent, reproducible evidence exists
for the exact shipping build and security constraints; do not
publish a support feed entry from stock source resemblance or
experimental DWARF alone.

## How we collaborate

Send the **Stage A readiness summary first**. If the nine states
are as expected, run **Stage B** and send the original source/code
excerpts (the runner prints them to the terminal). Review those
specific instructions, decide what they prove, then choose exactly
one next missing evidence gate. Do **not** execute all later stages
in advance.


## Current owner checkpoint — October 11, 2026

**Stage A passed**: 9/9 readiness tests and the exact expected
nine-stage statuses. **Stage B passed**: 69/69 source-code review
regressions; all eleven original disassembly windows and source SHA256
identities reverified. The owner preserved report
`hxl1-stock-rtmutex-source-code-03.md`.

A subsequent **direct original 568-byte** `remove_waiter` disassembly
captured all the major normal and exceptional branches through the
next recovered text-symbol boundary. Original stock instructions now
provide strong, source-consistent candidate associations for the
current-task PI lock, PI-blocked-on state, tagged lock owner,
and owner blocked-on-lock followup. The relevant original code SHA256
and precise provenance cautions are recorded in
[`ROOT_PAYLOAD_RESEARCH.md`](../research/y2q-G986U1UESCHXL1/ROOT_PAYLOAD_RESEARCH.md).
No original BTF/DWARF or factory debug member declarations have been
recovered; Stage 3 remains **PARTIAL**.

**Do not rerun Stage A/B, compile new Clang18 objects, or run a broad
script suite.** The next single check is a read-only lookup of
the **already-recovered** `vmlinux-stock.nm` for the actual branch/call
target symbol names, alongside original header declarations:

```bash
cd ~/src/Root-My-Galaxy-Payloads
NM="$HOME/s20-artifacts/hxl1-research/vmlinux-stock.nm"
grep -iE '^(ffffff8008146ca4|ffffff80080fafb4|ffffff800996d544|ffffff800996d774|ffffff800996d664|ffffff800996d83c)[[:space:]]' "$NM" || true

STOCK="$HOME/src/samsung-y2q-hxl1-stock"
grep -nE -C 4 'struct rt_mutex_waiter|struct rt_mutex \{|pi_lock|pi_waiters|pi_blocked_on' \
  "$STOCK/include/linux/rtmutex.h" \
  "$STOCK/include/linux/sched.h" | head -n 120
```

If all or some target names are missing, record the omission;
do **not** manufacture or import a substitute from a different
device. Inspect those precise branch destinations using the existing
recovered Image and disassembler only when essential. Distinguish
original machine-code member-location candidates from independently
established complete factory layouts. Continue only after evaluating
this output, then select one remaining proof gap.


### Owner checkpoint: stock `remove_waiter` call graph verified

The owner's next read-only WSL check resolved **all six** selected
original stock static-call destinations in
`vmlinux-stock.nm`: `rt_mutex_adjust_prio_chain`,
`rt_mutex_setprio`, `_raw_spin_lock`,
`_raw_spin_lock_irq`, `_raw_spin_unlock`,
and `_raw_spin_unlock_irq`. Original headers also confirm the
presence and ordering of `rt_mutex.wait_lock/waiters/owner`
and `task_struct.pi_lock/pi_waiters/pi_top_task/pi_blocked_on`.

This completes the **targeted original call-identity check**; do
not rerun it. It strengthens source-to-factory-instruction evidence,
**not** complete factory field-layout provenance or root feasibility.

**Next one evidence gate — original nested RT-mutex/waiter declarations:**

```bash
cd ~/src/Root-My-Galaxy-Payloads
STOCK="$HOME/src/samsung-y2q-hxl1-stock"
for src in \
  "$STOCK/kernel/locking/rtmutex.c" \
  "$STOCK/kernel/locking/rtmutex_common.h" \
  "$STOCK/include/linux/rtmutex.h"; do
  if [ -f "$src" ]; then
    echo "===== $src ====="
    grep -nE -C 10 \
      'struct rt_mutex_waiter[[:space:]]*\{|rt_mutex_top_waiter\(|rt_mutex_owner\(|task_blocked_on_lock\(' \
      "$src" | head -n 175
  fi
done
```

Review only which original structures, inline helpers and pointer
relationships the stock `remove_waiter` accesses can corroborate.
A source-level nested definition, even with these corroborating
machine instructions, does not authenticate *every* packed/aligned
member in the OEM compiled binary. Retain Stage 3 **PARTIAL**
and continue to Stage 4–5 runtime-evidence prerequisites as
independent gates only when there is a specific remaining proof
question. Nothing here authorizes kernel memory writes or a
KernelSU support-feed entry.


### Completed: Original waiter/helper correlation (owner WSL verification)

Owner confirmed the exact original `rtmutex_common.h` source
defines `struct rt_mutex_waiter`, the `rt_mutex_top_waiter()`
cached-first-node and `BUG_ON(w->lock != lock)` path, the
tagged `rt_mutex_owner()` accessor, and
`task_blocked_on_lock() -> p->pi_blocked_on->lock`.
These source relationships fit the original stock `remove_waiter`
load/branch chain: `lock+24` top cached waiter,
`waiter+56` lock pointer, `lock+32` owner pointer,
and owner/current task PI accesses near
`+0x8c8`/`+0x8e0`/`+0x8f8`.
Conditional `CONFIG_DEBUG_RT_MUTEXES` layout changes remain
a separate verification requirement for any field after the
optional debug members, such as `prio`.

**Stop looping on RT-mutex structure scans.** The selected
source-to-binary operation correlations are now sufficiently
documented as observations, but the **complete OEM ABI remains
PARTIAL**. They do not provide arbitrary kernel read/write,
a runtime kernel pointer or a valid KernelSU loading path.

### Next gate: review *existing* Stage 4/5 evidence, not a new sweep

The exact original ABL LinuxLoader static handoff was already
documented, and the prior device-side, read-only ADB evidence
did not measure the actual UEFI `KernelBaseAddr`/base-memory
branch, KASLR value, physical kernel entry or confirmed
booted DTB. Rather than rerun that denied/restricted probe,
read the retained results and identify whether the device
exposes a new legitimate source of runtime evidence:

```bash
cd ~/src/Root-My-Galaxy-Payloads
BASE="$HOME/s20-artifacts/hxl1-research"

echo "=== Existing Stage 4 static handoff ==="
sed -n '1,115p' "$BASE/abl-linuxloader/rea-stage4-handoff-static.md"

echo "=== Already retained live ADB reports (do not re-probe) ==="
find "$BASE/live-adb" -type f -name live-boot-evidence.md -print 2>/dev/null |
  sort | tail -n 5

echo "=== Exact HXL1 signed-module/kernel-probe gates ==="
gzip -dc "$HOME/s20-artifacts/config.gz" |
  grep -E '^(CONFIG_MODULES=|CONFIG_MODULE_SIG_FORCE=|CONFIG_KPROBES=|# CONFIG_KPROBES is not set|CONFIG_RT_MUTEXES=|CONFIG_FUTEX_PI=|CONFIG_DEBUG_RT_MUTEXES=|# CONFIG_DEBUG_RT_MUTEXES is not set)' || true
```

**Decision:** With no new independent runtime evidence,
do **not** claim a physical load/KASLR number, GhostLock
exploitation, root or KernelSU. Existing forced module-signature
checks and `CONFIG_KPROBES=n` must be treated as real design
obstacles. The next engineering milestone is *feasibility of
an authorized runtime privilege/code-loading primitive on the
exact locked HXL1 build*, not another Clang18 object or
truncated disassembly. Stage 7 stays BLOCKED.


## October 11 owner checkpoint — verified exact kernel config; runtime-feasibility decision

Owner ran the existing host-only review at commit `d820195`.
The original authenticated static LinuxLoader handoff showed:
`KernelEntry = KernelBaseAddr + imageFormatBias + (KASLRState << 15)`
or `KernelEntry = (BaseMemory | OEMImageFormatOffset) +
(KASLRState << 15)`. The `0x40` KASLR initializer is a **sentinel**,
not a measured runtime displacement. Neither the selected branch,
per-boot RAM base, actual DTB nor physical target was observed.

There are already TWO local, retained, read-only ADB reports:
`live-adb/20261010T130008Z/live-boot-evidence.md`
and `live-adb/20261010T130021Z/live-boot-evidence.md`.
**Read them, but do not reissue blocked/restricted device probes.**

Owner's current exact `config.gz` confirms:

| Option | Owner observed | Gate |
|---|---|---|
| `CONFIG_FUTEX_PI` | `y` | Subsystem built in; exploitability **not** proved |
| `CONFIG_RT_MUTEXES` | `y` | Source/code consistency |
| `CONFIG_DEBUG_RT_MUTEXES` | **not set** | Non-debug waiter struct selected; conditional debug fields absent |
| `CONFIG_MODULES` | `y` | Module framework built |
| `CONFIG_MODULE_SIG_FORCE` | `y` | Normal untrusted module insertion denied |
| `CONFIG_KPROBES` | **not set** | Existing KernelSU kprobe/kretprobe path unavailable |

The non-debug waiter priority candidate at offset `0x40`
in original `remove_waiter` is now additionally supported by the
configuration: two `struct rb_node` fields, task and lock pointers,
then `prio`. This **does not** establish a complete factory ABI.

**Focused next host-only action: summarize only *existing*
runtime observation statuses** without dumping private bootargs,
addresses or repeating ADB requests:

```bash
cd ~/src/Root-My-Galaxy-Payloads
python3 - <<'PY'
import json
from pathlib import Path
base=Path.home()/"s20-artifacts/hxl1-research/live-adb"
for path in sorted(base.glob("*/live-boot-evidence.json")):
    report=json.loads(path.read_text())
    print("REPORT",path.parent.name)
    print("  iomem:",report.get("iomem",{}).get("status","UNAVAILABLE"))
    props=report.get("bootProperties",{})
    for field in ("ro.boot.dtb_idx","ro.boot.dtbo_idx"):
        print(" ",field+":",props.get(field,"[UNAVAILABLE]"))
    for field in ("proc_cmdline","proc_bootconfig","proc_iomem",
                  "proc_dt_bootargs","sys_dt_bootargs","proc_dt_model",
                  "sys_dt_model"):
        print(" ",field+":",
              report.get("fileObservations",{}).get(field,{}).get("status",
              "NOT_COLLECTED"))
    for flag in ("physicalKernelEntryVerified",
                 "runtimeKaslrMeasured",
                 "runningDtbMatchedToBootloaderSelection"):
        print(" ",flag+":",report.get(flag,"NOT_COLLECTED"))
PY
```

**Acceptance criteria:** If the past device observations contain a
grounded DTB index, check against existing FDT candidate records;
otherwise document that specific limitation. An absent/restricted
IOMEM or bootargs never licenses guessing the physical address or
forcing access. ADB unprivileged shell cannot establish UEFI
KernelBaseAddr/KASLR independently on this evidence alone.

**Primary go/no-go:** With the locked bootloader, forced module
signatures and no kernel probes, the exact-device native/KernelSU
path is **BLOCKED** until a demonstrable authorized kernel-code
execution mechanism and compatible hook backend are available.
No stock source resemblance, linker symbol or futex-PI smoke test
alone satisfies this. Do not produce/flash an HXL1 module or
declare the profile supported.

**Engineering priority:** Obtain *new evidence* of an authorized
privileged loading route or a safely demonstrated HXL1-specific
runtime bug in an isolated reproduction. Until then preserve
the research profile and do not run another broad static scan.


## October 11 checkpoint — exact reported DTB/DTBO indices

The owner inspected *two already-retained* HXL1 device ADB records
(`20261010T130008Z` and `20261010T130021Z`, just 13 seconds apart).
Both give:

- `ro.boot.dtb_idx=0` and `ro.boot.dtbo_idx=2`;
- `/proc/cmdline`, `/proc/iomem`, both device-tree root
  `model` and `chosen/bootargs` interfaces: **PERMISSION_DENIED**;
- `/proc/bootconfig`: **NOT_PRESENT**;
- no verified physical Linux kernel load/entry, runtime
  KASLR or effective DTB hash.

These are two observations, **not independent boot measurements**.

The *offline* embedded stock boot-v2 region has four validated
contiguous FDTs in **one-based report order**:
candidate 1 Kona v2.1 at offset `0x0`,
candidate 2 Kona v2 at `0x81088`,
candidate 3 Kona v1 at `0x10210c`,
candidate 4 minimal 173-byte tree at `0x181c46`.
Its first bytes are FDT magic, **not** Android DT-table magic.
The selector's index base and its mapping to these four bytes
are **not independently established**. Therefore the observed
`dtb_idx=0` does NOT certify that first candidate is running.
The observed `dtbo_idx=2` is in a distinct *overlay* selection
domain, **not** candidate 3 of the four embedded base FDTs.

**Completed (owner WSL2):** No `dtbo.img`, `dtbo.img.lz4`
or `dtbo.bin` was found within five subdirectory levels under
`~/s20-artifacts`. The four original base FDT identities remain
unchanged. Record
`HXL1_ORIGINAL_DTBO_TABLE_NOT_IN_LOCAL_EVIDENCE`, not
`NO_DTBO_PARTITION_EXISTS`.
The `dtb_idx=0` and `dtbo_idx=2` properties are preserved
as bootloader selection hints only. No DTBO index or effective
tree hash is independently proven.

**Stop repeating the firmware/DTB and restricted ADB loops.**
A separate DTBO extraction or older Samsung FUS metadata lookup
should be reopened only if a concrete implementation or recovery
gate actually requires that evidence.

### Next consequential engineering milestone — isolated runtime feasibility

The original HXL1 `remove_waiter` bug-pattern, its stock
compiled access paths, selected struct member candidates and
six call destinations are documented. The pre-existing ARM64
QEMU lab booted **upstream** Linux 4.19.325 with debugging,
but did **not** reproduce the OEM HXL1 proxy-lock rollback
behavior, and did **not** match the device's complete Samsung
kernel or security policy. The target kernel is
`4.19.113-27095354`, not upstream 4.19.325.

Any further work must use a **safe, isolated, source-exact
regression** that distinguishes the potentially incorrect
`current`/waiter task cleanup branch from its patched
counterpart. It should measure only bounded state/lock
integrity in a disposable instrumented guest, not induce
unstable futex races on the real phone. First verify the
lab's actual source and configuration fidelity; if
HXL1 code cannot run there faithfully, treat reproduction
as `NOT_TESTED` rather than transferring upstream
results to the stock handset.

A demonstrated **cleanup bug is not automatically an exploitable
kernel read/write primitive**. A demonstrated primitive would
still not give KernelSU installation automatically.
The live `SM-G986U1` remains verified-boot locked with
`CONFIG_MODULE_SIG_FORCE=y` and
`CONFIG_KPROBES=n`; an independently verified
privileged code-loading route and a compatible Linux 4.19
hook/backend design remain absent. No root/profile release
until these are established.

**Current readiness:** Stages 1–2 COMPLETE, Stage 3 PARTIAL,
Stages 4–6 OPEN, Stages 7–8 BLOCKED, Stage 9 DEFERRED.
