## Independently rechecked original HXL1 archive — two-hop machine-code evidence (October 14, 2026)

The actual previously uploaded `hxl1-disassembly-review.tar.gz` was present in the conversation files and **independently rehashed** in the analysis environment: `20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997`. Its `do_futex.disasm.txt` has SHA-256 `56286516ae9e6a873beab22b16af3ab330a768dc1b02f901854eb96f193789a5`, containing **1,766 contiguous AArch64 instructions**. The stored manifest's original Image SHA is `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`; **the complete Image was not rehashed in this new pass**.

The original operation-11 dispatcher compares `w8, #0xb` at `do_futex + 0xb14` and conditionally branches from `+0xb18` to `+0xbd0`. The exact two-hop branch exploration stopped at the next explicit branch per block:

| Depth | Static block start relative to do_futex | Consecutive instructions | Terminator | Literal BL calls |
| ---: | --- | ---: | --- | ---: |
| 0 | `+0xbd0` | 24 | `b.eq` at `+0xc2c` | 0 |
| 1 | `+0xc30` | 1 | `cbz` | 0 |
| 1 | `+0x117c` | 2 | `b` | 0 |
| 2 | `+0xc34` | 16 | `b` | 3 |
| 2 | `+0x118c` | 11 | `cbnz` | 2 |
| 2 | `+0x128c` | 2 | `b` | 0 |

These are six **alternative static control-flow blocks**, not 56 instructions in a single runtime invocation. The two alternatives reached from `+0xc30` are `+0xc34` and `+0x118c`; the `+0x117c` block unconditionally branches to `+0x128c`. Across the depth-two alternatives, five original static direct branch-with-link callsites are found:

- `do_futex +0xc48` → static target `0xffffff8008179e84`
- `do_futex +0xc58` → static target `0xffffff800817a86c`
- `do_futex +0xc68` → static target `0xffffff8008179084`
- `do_futex +0x1198` → static target `0xffffff80081474fc`
- `do_futex +0x11b0` → static target `0xffffff80081930ec`

These five direct target addresses are confirmed from the archived original **instruction text**; the independent archive-only review did not reload the original recovered `vmlinux-stock.nm` and therefore **does not newly certify callee labels**, source-level argument objects, helper inlining or actual runtime branch feasibility. The original op-11 first-block observation of **zero** BL calls remains correct only for that first block. The 5 subsequent sites disprove any claim that the two-hop bounded region contains no BL instructions.

Machine-readable evidence checkpoint: `research/y2q-G986U1UESCHXL1/ghostlock-op11-original-twohop-20261014.json`. The existing one-command `tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh` and existing analyzer now implement two-hop enumeration, verify exactly the six pinned block/count triples and report the five calls with static recovered-symbol lookups on the owner host. Four extra synthetic regression tests bring the suite from 18 to **22**. No owner or hosted test result for these new changes has been observed yet.

To verify on WSL using the same authenticated archive, run:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

This performs no root attempts, kernel mutations, device operations or firmware re-extraction. No compiled `rt_mutex_waiter` C-local identity, waiter lifetime, cross-syscall memory overlap, live exploit primitive or KernelSU has been established. Stage 3 remains PARTIAL.

---

## Owner result — 08:35:39 UTC; bounded successor audit extension

The owner ran the original single-block runner after pulling `b37bf5d`. All **13/13 original regression tests passed**, and the exact cached HXL1 archive and original NM validation succeeded. **The first compiled operation-11 block begins at `do_futex + 0xbd0`, contains 24 consecutive AArch64 instructions, and has no direct `bl` calls before an explicit control transfer.** The original output is `/home/main/s20-artifacts/hxl1-research/ghostlock-original-futex-op11-20261014T083539553990891Z.json`; its full bytes were not uploaded. The terminating opcode and branch operand are **not visible in the pasted terminal output**, so they cannot yet be classified.

This is an authentic static code-window boundary, **not** proof of a missing helper, inlining, waiter stack storage, or an impossible exploit. Do not claim zero calls across the entire operation-11 control-flow subgraph from a zero-call first block.

An extension to the **same** `tools/y2q_hxl1_ghostlock_futex_op11_block.py` now captures the first block's terminal opcode and operand and, when an explicit conservative control-flow edge exists, examines **only its immediate successor blocks**. The bounds are two successors maximum and 64 contiguous instructions each, stopping at the first control transfer. Any branch back to the first block is recorded as a cycle and not re-traversed. The extended output contains each inspected opcode and operand, any direct call target resolved against the pinned recovered NM, and flags confirming runtime-path feasibility, pointer flow, helper identity, and waiter-slot attribution are **not verified**.

Five new synthetic regression tests were added, bringing the suite to **18 tests**, and the existing CI workflow already tracks these exact files. The original 13 passed on the owner host; the new 18-test suite, one-hop algorithm, and original-pinned successor output have **not yet been observed running**.

The same runner is used; it reuses the SHA-pinned archive and recovered NM without another firmware extraction or device operation:

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

The saved JSON, not just the console summary, provides detailed one-hop original code findings. For a concise review:

```bash
python3 - "$HOME/s20-artifacts/hxl1-research" <<'PY'
import json,sys
from pathlib import Path
paths=sorted(Path(sys.argv[1]).glob("ghostlock-original-futex-op11-*.json"))
if not paths:raise SystemExit("No op11 report found")
r=json.loads(paths[-1].read_text())
b=r["operation11LinearBlock"]
print("First block:",b["case11BlockStartRelativeToDoFutexEntry"],"instructions:",b["originalLinearInstructionSlotsReviewed"])
print("Terminal:",b["terminalControlTransfer"])
for x in b["immediateSuccessorBlocks"]:
    print("One-hop:",x["relativeToDoFutexEntry"],x["status"],
          x.get("instructionSlots"),x.get("stopReason"))
    for call in x.get("directCalls",[]):
        print("  Branch-to:",call)
print("Waiter compiler-local identified:",r["exactFutexWaiterCompilerLocalProven"])
PY
```

**Evidence boundary unchanged:** Source-local waiter lifetime is supported by the pinned original Samsung source; compiled C-local position, stack reuse, live GhostLock operation and KernelSU remain unverified. Stage 3 stays PARTIAL.

---

# HXL1 GhostLock — original operation-11 compiled branch gate (2026-10-14)

**Research-only.** Samsung Galaxy S20+ SM-G986U1, original G986U1UESCHXL1 Linux 4.19.113-27095354. No GhostLock payload, root execution, kernel patch, phone access, KernelSU deployment, runtime physical addresses or support-feed changes.

## Latest owner result, 08:17:55 UTC

The owner pulled through `b76bfb3`, ran `tools.test_y2q_hxl1_ghostlock_helper_classes` and confirmed **10/10 passing tests**. The original stock sendmsg-family call graph remains **41 direct callsites**, **21 distinct immediate branch destinations**, all **21/21 exact recovered labels**, with 3 calls to the Samsung `jopp_springboard_blr_x8` trampoline. The branch sites are:

- `__sys_sendto` → JOP springboard: `0xffffff800966eb70`
- `___sys_sendmsg` → JOP springboard: `0xffffff800966f498`
- `___sys_sendmsg` → JOP springboard: `0xffffff800966f4e0`

All three jump to the recovered springboard address `0xffffff800997463c`. Their *effective* x8-mediated callees are **not verified**. A static label is not a decoded pointer value.

The 41 calls are fully accounted for across helper classes: allocation/free 4, compat conversion 2, file descriptor acquisition/release 7, iovec and address copy 9, JOP trampoline 3, memory primitives 5, security checks 2, sendmsg internal 4, and stack-protector failure paths 5. Counts are code sites, **not** runtime frequencies, paired object allocation/free or a stack-reuse relationship. The original crosswalk file fingerprint reported by the owner is `94be240898b54c51ef428e2813b3ed143117de37d2a1098c0238db076d15badd`; the terminal paste itself is not the original standalone JSON byte stream.

The machine-readable checkpoint is `research/y2q-G986U1UESCHXL1/ghostlock-owner-helper-classes-20261014T081755Z.json`.

## Next substantive question: original compiled futex operation 11

Our existing original-source `kernel/futex.c` and `fs/select.c` lifetime-contract audit already documented **30 source landmarks**, including `struct rt_mutex_waiter rt_waiter`, assignment of `q.rt_waiter = &rt_waiter`, the proxy-lock and cleanup sequences, and the source-local select frame. The existing, hash-verified five-function original `do_futex` archive proved a `cmp w8, #0xb` and a taken-case branch **within the same compiled `do_futex` window**, with 4,102 total original instruction slots and conservative case-11 graph reachability. This **does not** prove the C helper was inlined or identify its stack-local compiler slot.

The new `tools/y2q_hxl1_ghostlock_futex_op11_block.py` reuses only that authenticated archived disassembly and exact recovered NM. It:

1. Requires SHA-256 `20edab24364b4ae269b99bf20434f93cf10212f92e5cf791582549ae82bf9997` for the existing `hxl1-disassembly-review.tar.gz`, and applies the existing archive validation (five text digests, contiguous instruction windows and original operation-11 reachability).
2. Requires original recovered `vmlinux-stock.nm` SHA-256 `c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f`.
3. Locates only the original compiled operation-11 branch destination, then collects **at most 128 sequential instructions** to the next explicit control transfer or recovered function-window end.
4. Reports any literal direct BL call in that *one* bounded basic block, resolving only exact recovered symbols or explicitly uncertain interior label intervals. It does not follow other blocks or assume the branch was executed on the phone.
5. Refuses to infer compiled C-local identity, waiter placement, source-helper inlining, blocking syscall lifetime, stack overlap, exploitability or root. Does not create a target header or execute any exploit.

Thirteen new fail-closed regression tests and the one-command runner are committed and wired to `.github/workflows/hxl1-ghostlock-stack-gate-ci.yml`. **New suite owner and CI results are pending**; do not claim 13/13 passing.

### One-off owner WSL command

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

The runner tests the new code, locates only already saved, SHA-matching disassembly files in the owner's HOME/research directory, reads the cached recovered NM and writes a fresh JSON under `~/s20-artifacts/hxl1-research`. If the original archive has been moved elsewhere, provide it explicitly without replacing the evidence:

```bash
HXL1_DISASSEMBLY_ARCHIVE="/actual/path/hxl1-disassembly-review.tar.gz" \
  bash tools/run_y2q_hxl1_ghostlock_futex_op11_block.sh
```

No new firmware download, Odin flash, QEMU replay, ADB, Ghidra or REA run is performed. The original archive contains original-Image-derived disassembly text and manifest, but not a newly rehashed whole `kernel.bin`; the new tool says `originalKernelImageRehashedByThisAudit=false`.

**Readiness unchanged:** Stage 3 PARTIAL; stages 4–6 OPEN; stages 7–8 BLOCKED; stage 9 DEFERRED. Authenticated original source+branch evidence is not a demonstrated GhostLock exploit or KernelSU installation.
