# HXL1 GhostLock — 21/21 recovered sendmsg call labels (2026-10-14)

**Target:** Samsung SM-G986U1, HXL1 G986U1UESCHXL1, stock Linux 4.19.113-27095354. **Scope:** read-only static original Image and recovered kallsyms. No root exploit, payload, device write, runtime kernel address or KernelSU activation.

## Owner result

Owner WSL command pulled through branch revision 3c59afc; 12/12 tests passed in tools.test_y2q_hxl1_ghostlock_call_target_crosswalk. The run reported 41 original direct BL callsites, 21 unique direct destinations, and **21 exact recovered text-label matches**. Output retained on owner host as /home/main/s20-artifacts/hxl1-research/ghostlock-call-targets-20261014T080638Z.json. This terminal output was pasted into conversation; the standalone JSON was not independently uploaded or byte-hashed in this checkpoint.

Kernel Image SHA-256 pinned: ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123.
Recovered Nm SHA-256 pinned: c2306a026756230fb009576613c07e5461cccf8fd92ca5f72a52647933870f2f.
The original six function code windows and their 746 native instruction slots were separately verified on the owner host.

### Actual original HXL1 branch destination labels

| Recovered original call destination label | Static BL callsites |
| --- | ---: |
| __stack_chk_fail | 5 |
| __kmalloc | 1 |
| kfree | 1 |
| __check_object_size | 2 |
| fput | 4 |
| __fdget | 3 |
| security_socket_sendmsg | 2 |
| import_iovec | 1 |
| import_single_range | 1 |
| move_addr_to_kernel | 2 |
| ___sys_sendmsg | 3 |
| copy_msghdr_from_user | 1 |
| sock_kmalloc | 1 |
| sock_kfree_s | 1 |
| get_compat_msghdr | 1 |
| cmsghdr_from_user_compat_to_kern | 1 |
| __arch_copy_from_user | 3 |
| __pi_memcmp | 1 |
| __memcpy / __pi_memcpy (same recovered address) | 1 |
| __memset / __pi_memset (same recovered address) | 3 |
| jopp_springboard_blr_x8 | 3 |
| **Total** | **41** |

The six functions have 4, 15, 7, 6, 4 and 5 calls respectively (in order __sys_sendmsg, ___sys_sendmsg, __sys_sendto, __sys_sendmmsg, rw_copy_check_uvector, copy_msghdr_from_user). The original __sys_sendmsg and __sys_sendmmsg entry routines call ___sys_sendmsg three times in total; the latter calls copy_msghdr_from_user.

**Critical distinction:** all 21 *direct branch destinations* have recovered text labels. Three of the 41 branches go to a **named Samsung JOP springboard**, not necessarily to the final function executed via the springboard. The name jopp_springboard_blr_x8 suggests an x8-mediated indirect call, but the value in x8 and the actual springboard implementation have not yet been independently established from its exact original instruction bytes. Do not promote 21/21 matches to complete effective-callee resolution. The five __stack_chk_fail branches are compiler guard/failure sites, not measured runtime hot-path calls. Both __kmalloc/kfree and sock_kmalloc/sock_kfree_s are *separate identified branches*; their object identities, matching allocation/free pairs and lifetime are not proven.

## Committed automated next pass

tools/y2q_hxl1_ghostlock_helper_classes.py is a no-device, fail-closed semantic **bookkeeping** layer over the exact owner crosswalk. It requires 21 distinct recovered labels, 41 total callsites, all six prior caller counts, the HXL1 NM and Image identity pins, and the four known internal edges. It outputs an inventory by helper family and keeps the **three named JOP trampoline callees unresolved**. It refuses upstream assertions of exploit success, pointer flow or device modification.

The companion tools/test_y2q_hxl1_ghostlock_helper_classes.py has 10 regression cases for counts, aliases, forged pointer-flow claims, changed symbol IDs, missing known edges, duplicate callsites, and isolated direct CLI imports. It is integrated into the HXL1 GhostLock CI workflow. New owner/hosted test execution and output are **pending**; do not claim 10/10 PASS.

### One bounded WSL run

    cd ~/src/Root-My-Galaxy-Payloads
    git pull --ff-only

    python3 -m unittest -v tools.test_y2q_hxl1_ghostlock_helper_classes

    EVIDENCE="$HOME/s20-artifacts/hxl1-research"
    OUT="$EVIDENCE/ghostlock-helper-classes-$(date -u +%Y%m%dT%H%M%SZ).json"
    python3 -m tools.y2q_hxl1_ghostlock_helper_classes \
      --crosswalk "$EVIDENCE/ghostlock-call-targets-20261014T080638Z.json" \
      --output "$OUT"

    python3 - "$OUT" <<'PY'
    import json,sys
    d=json.load(open(sys.argv[1],encoding="utf-8"))
    print("Stock callsites:",d["staticCallsites"])
    print("Distinct immediate destinations:",d["distinctImmediateBranchDestinations"])
    for label,count in d["staticCallsitesByHelperClass"].items():
        print(label,count)
    print("Unresolved JOP callee calls:",d["branchToNamedJopTrampolineCount"])
    print("Waiter stack alias:",d["futexWaiterSendmsgStackAliasVerified"])
    PY

This step requires **no re-extraction**, no new Image disassembly, no ADB or REA and no GhostLock execution. The result is a categorized label summary, not new runtime capabilities.

### Stop/go recommendation

**Already demonstrated:** original rtmutex source bug pattern, select/futex opcode snippets, the stock sendmsg-family function frames, 746 instruction slots, and 21 exact direct-target recovered labels.

**Still absent:** exact compiled rt_mutex_waiter stack-local identity and lifetime in the HXL1 futex path; proven source-object identity of sendmsg SP-relative buffers and whether a call can actually retain a matching kernel stack window; effective springboard x8 targets; authenticated runtime kernel layout/KASLR; a live GhostLock primitive; KernelSU authorization.

The next significant proof would be an original HXL1 futex waiter and sendmsg **source-to-machine attribution**, not another K40-based estimate or generic call count. Stage 3 PARTIAL, stages 4–6 OPEN, stages 7–8 BLOCKED, stage 9 DEFERRED. Root/KernelSU is NOT validated.

Research checkpoint: research/y2q-G986U1UESCHXL1/ghostlock-sendmsg-21-exact-symbols-20261014.json.
