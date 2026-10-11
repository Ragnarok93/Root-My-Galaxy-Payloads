# HXL1 — isolated cleanup ownership regression

**Original firmware:** SM-G986U1 / G986U1UESCHXL1, kernel `4.19.113-27095354`.

This is a user-space **C state model** of the ownership/cleanup difference identified in the pinned Samsung RT-mutex source and the published 2026 correction. It does **not** compile/execute Samsung kernel code, trigger futex-PI races, load modules, touch the phone, or attempt root.

GitHub source and tests:
- `tools/y2q_hxl1_cleanup_regression.py`
- `tools/test_y2q_hxl1_cleanup_regression.py`

## Existing-local-source execution

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only
python3 -m unittest -v tools.test_y2q_hxl1_cleanup_regression
python3 tools/y2q_hxl1_cleanup_regression.py \
  --source "$HOME/src/samsung-y2q-hxl1-stock" \
  --output "$HOME/s20-artifacts/hxl1-research/cleanup-model.json"
```

This validates the two exact Samsung C hashes and six source indicators already defined in `tools/y2q_rtmutex_fix_audit.py`. It compiles a small `-O0 -Wall -Wextra -Werror` C program using the host `cc` into a temporary directory and executes ten deterministic model scenarios. It creates a **new** report file; it refuses overwriting an existing one or writing into original source.

**Model-only expected results:** `current != waiter->task` and a simulated negative return cause the stock rule to clear `current`'s modeled PI state while leaving the waiter task's modeled state untouched; the corrected rule does the reverse. The model also contrasts original nonzero-result cleanup with corrected negative-result cleanup and a never-enqueued guard.

**Evidence gates:** `modelConditionalMismatchDemonstrated=true`, while `originalSamsungKernelExecuted`, `sourceExactKernelGuestReproduced`, `hxl1RuntimeReachabilityProven`, `rootPrimitiveVerified`, and `kernelSuInstallable` **must remain false**. Any downstream pipeline must treat a passing model as *source ownership semantics only*, not a successful privilege escalation.

**Next actionable kernel-level gate:** For source-faithful reproduction, the actual patched Samsung RT-mutex and futex code must execute in a disposable isolated guest with matching configuration and controlled instrumentation. The existing upstream 4.19.325 QEMU image is insufficient. If the Samsung build cannot be reproduced in an isolated guest, mark `NOT_TESTED`, not `PASS`. Never trigger these races on the production phone.
