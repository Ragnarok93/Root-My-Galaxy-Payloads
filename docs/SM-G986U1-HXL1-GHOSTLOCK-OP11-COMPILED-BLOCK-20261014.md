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
