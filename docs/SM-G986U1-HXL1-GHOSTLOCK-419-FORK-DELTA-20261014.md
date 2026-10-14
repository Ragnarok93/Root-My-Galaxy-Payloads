# SM-G986U1 HXL1 — GhostLock Linux 4.19 fork-delta audit (2026-10-14 UTC)

**Scope:** original Samsung SM-G986U1/G986U1UESCHXL1 kernel 4.19.113-27095354, research-only. This checkpoint compares existing HXL1 proof against the current K40 4.19 development fork. It does not build or run an exploit, change the handset, emit a target header, or authorize a KernelSU module.

## Already established on HXL1 (do not repeat)

Original Samsung kernel/locking/rtmutex.c has SHA-256 36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9. Original kernel/futex.c is 493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5. The stock extracted kernel.bin SHA-256 pin is ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123.

Prior HXL1 source, limited OEM compiled-byte, ARM64 CFG, select allocation and Clang10 comparison audits support the CVE-2026-43499 erroneous-current-task cleanup **bug pattern** and selected associated machine code; the recovered do_futex case 11 is statically reachable. These do not demonstrate a freed waiter's factory stack slot, cross-syscall alias, KASLR disclosure, user-controlled corruption, or an actual root chain.

Readiness is still: stages 1–2 complete, 3 partial, 4–6 open, 7–8 blocked, 9 deferred.

## Surveyed relevant 4.19 forks and current evidence boundary

Main research comparison is ccp-p/ghostlock-cve-2026-43499-4.19-k40 at commit 68f191029f20162de3c402935c2f0213210e2de6 (2026-09-17). The smaller yijiacloud/ghostlock-cve-2026-43499-4.19-k40 fork is an earlier 4.19 baseline; neither is a Samsung HXL1 port.

The ccp-p snapshot is authenticated via these Git blob SHA1s:

| Exact fork source | Git blob SHA1 |
|---|---|
| docs/status.md | 5c9fd4a613741d267ac9bd660efcb3c0635b315f |
| docs/specs/kernel-frame-placement-enumeration.md | c4a6beccfdfc447f0fed8b42e4be99daa25294cf |
| docs/specs/rt-waiter-placement-audit.md | 8e54b1346a934e66999a6a902bce27503130f206 |

The fork status table still marks milestone 3 candidate convergence and milestone 4 root chain blocked. Its appended September 15–16 research describes a K40-specific frame-placement hypothesis based on adjacency of the native sendmsg iovstack and address objects, supported by that device's compiled kernel code. A K40 device trial reported sendmsg returned 65540 (the complete carrier length) prematurely, so the carrier did not maintain its intended kernel stack window. A subsequent deterministic TCP blocking redesign was built offline, but that status entry does not verify successful HXL1 behavior, a complete K40 root chain, or reliable runtime control.

Critically, the K40 source build was 4.19.157-perf, Snapdragon 870/alioth, while HXL1 is 4.19.113-27095354, Samsung y2q Snapdragon 865. K40's selected compilation, VA/PA constants, stack offsets, waiter placement, rtmutex field offsets, allocator geometry, CONFIG/security settings and actual execution results CANNOT be transferred merely because Linux major/minor is 4.19.

## Completed code advancement

New tools/y2q_hxl1_ghostlock_crossfork_419_gate.py is an **offline fail-closed source and reference gate**:

1. Authenticates the exact original Samsung rtmutex and futex source bytes with the already established SOURCE_PINS via tools/y2q_hxl1_kernel419_compatibility.py.
2. Reuses that module's conservative 4.19 API inventory. Optionally checks original net/socket.c and fs/read_write.c for relevant source identifiers, hashing whatever exact files are present. Missing optional source is reported, not silently treated as proof of absence.
3. Authenticates all three frozen K40 fork documentation blobs and checks for the corresponding root-chain and sendmsg findings. A different checkout yields a **reference revision drift stop**, not a silent change of conclusions.
4. Returns a structured matrix explicitly marking compiled HXL1 waiter/sendmsg overlap, K40 collision evidence, KASLR/physical assumptions, runtime primitive and KernelSU as NOT verified.
5. Writes a fresh report only outside the stock source tree, reference tree and this Git repository. No payloads, candidate target.h, root commands or new kernels are built.

Ten synthetic fail-closed tests are checked in and added to the existing HXL1 GhostLock CI workflow; owner/hosted success for these new tests is pending. These tests cover source pin changes, fork blob drift, blocked-root status, recorded premature sendmsg return, missing optional source, mismatched bug pattern, and standalone CLI import.

### One-shot existing-owner-worktree validation

The owner previously cloned the K40 fork under HOME. First check source identity and revision without altering existing work:

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only
    python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_crossfork_419_gate

    OUT="$HOME/s20-artifacts/hxl1-research/ghostlock-k40-hxl1-delta-$(date -u +%Y%m%dT%H%M%SZ).json"
    python3 -m tools.y2q_hxl1_ghostlock_crossfork_419_gate \
      --source "$HOME/src/samsung-y2q-hxl1-stock" \
      --reference-fork "$HOME/ghostlock-cve-2026-43499-4.19-k40" \
      --output "$OUT"
    test ! -s "$OUT" || cat "$OUT"

If the fork is stale or dirty and source docs do not match the SHA pins, the script intentionally exits 2. **Do not force-pull or reset a working research checkout.** Create a *separate*, clean checkout of the frozen reference instead:

    REF="$HOME/src/ghostlock-k40-reference-20261014"
    test ! -e "$REF" &&
      git clone https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40.git "$REF" &&
      git -C "$REF" checkout --detach 68f191029f20162de3c402935c2f0213210e2de6

Then rerun the checker with --reference-fork "$REF" and a NEW timestamped output. No phone connection is required. Never copy a K40 target.h or K40 compiled binary into src/targets/y2q or production support feeds.

## Next engineering decision

The strongest next independent evidence should be an **original Samsung HXL1 compiled-frame and source mapping** around the actual waiter-containing futex path and the original sendmsg path, not another source vulnerability scan. Existing five-function disassembly archive and exact Clang10 provisional objects must remain comparison-only where compiler locals and stack positions are not factory-authenticated. A verified alternate HXL1 compiled code window or matching original OEM debug artifact would materially improve this, but unprivileged ADB has already denied access to runtime DTB properties and does not provide a physical kernel base.

KernelSU 4.19 remains separately blocked by signed-module enforcement, absent kprobes and Samsung RKP/KDP/DEFEX. Source vulnerability does not disable those mechanisms.

Machine-readable checkpoint: research/y2q-G986U1UESCHXL1/ghostlock-k40-fork-delta-20261014.json.
