# SM-G986U1 HXL1 — Stage 3 compiled-member correlation (2026-10-11)

**Classification:** original kernel instruction displacements + exact-source-correlated *candidate* field names. **NOT a complete factory ABI profile** and **NOT root**.

## Evidence

Owner-exported `HXL1-Stage3-REA-Evidence.zip` contains three REA read_function_instructions reports and their SHA-pinned manifest; `HXL1-Stage3-Code-Slices.zip` contains the same three isolated original-Image-derived AArch64 ELF executable sections. The owner verified original `kernel.bin` SHA-256 `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123` and reconstructed `vmlinux-stock.elf` SHA-256 `e15f67e8253396d9e6463e5dfd78d67e324a7149842a7fbccb973ec0fd36ecdb` on WSL. Independently decoded with LLVM, all **723 of 723 REA instruction mnemonics and operands** agree and **38 manually constrained original instruction witnesses** were verified; **12 of 12** independent opcode/attribution tests passed.

## Subset compiled displacements

| Source member candidate | Original function-relative witness | Compiled displacement | Register/role evidence | Confidence boundary |
|---|---|---|---|---|
| `task_struct.pi_lock` | `remove_waiter+0x38`: `add x21,x20,#0x8c8` | `0x8c8` | `x20` originates in `mrs x20,sp_el0` at `+0x34` | Original bytes + HXL1 source correlation, **not factory DWARF** |
| `task_struct.pi_blocked_on` | `remove_waiter+0x68`: `str xzr,[x20,#0x8f8]` | `0x8f8` | **current** task field clear | Original bytes + HXL1 source correlation |
| `task_struct.pi_lock` | `remove_waiter+0x80`: `add x22,x21,#0x8c8` | `0x8c8` | At `+0x78`, `and x21,x24,#-0x2` redefines `x21` from lock owner bits | Original bytes + HXL1 source correlation |
| `task_struct.pi_waiters` | `remove_waiter+0xc4`: `ldr x12,[x21,#0x8e0]` | `0x8e0` | Owner PI waiter tree; **not** current-task pointer | Original bytes + source correlation; no debug-type offsets |
| `task_struct.pi_blocked_on` | `remove_waiter+0x150`: `ldr x8,[x21,#0x8f8]` | `0x8f8` | Owner task at this point | Original bytes + source correlation |
| `task_struct.pi_state_cache` | `futex_lock_pi+0x78`: `ldr x12,[x20,#0x9f8]`; `+0xf8`: `str x0,[x20,#0x9f8]` | `0x9f8` | x20 from `mrs x20,sp_el0`; cache allocation and store path | **Provisional** member name pending tighter original-source correspondence |

These numbers are **binary instruction displacements** relative to register-derived objects. They are not validated as a complete or generally usable `task_struct` layout. `rt_mutex_waiter` and `rt_mutex` full factory structures still have no proven debug-layout provenance.

## Additional static control flow

In `rt_mutex_start_proxy_lock` (recovered stock VA `0xffffff8008147d14`), the conditional `cbz w0,+0x68` at `+0x34` skips the `remove_waiter` call for a zero result. The **nonzero fallthrough** prepares `x0=lock` and `x1=waiter` and makes a direct `bl` at `+0x44` to the recovered `remove_waiter` VA `0xffffff8008147db4`; this is consistent with the pinned HXL1 source's `if (unlikely(ret))` cleanup condition. A separate second return branch at `+0x80` also conditions cleanup. **This proves branch structure, not runtime reachability, a race, or exploitation.**

In `remove_waiter`, `+0x19c` sets `x5=x20` (current) as sixth argument immediately before a compiled `bl` at `+0x1a0`; its callee has not been independently bound to a source symbol. Do not confuse synthetic ELF PC-relative `bl` addresses with actual runtime addresses or assert that the caller has executed.

The 2026 Linux upstream `remove_waiter` change uses `waiter->task` instead of `current`; this public upstream context supports review of the original Samsung source but **does not prove GhostLock applicability on the running handset**, usable kernel read/write, or KernelSU installation.

## Proof status

- Stage 1–2 remain COMPLETE.
- **Stage 3 remains PARTIAL** with a newly substantiated subset of factory-compiled displacements; no original factory DWARF/BTF, full `task_struct`/`rt_mutex_waiter` layout, or complete source-to-instruction debug binding.
- Stages 4–6 OPEN; KernelSU/deployment BLOCKED, release DEFERRED.
- No device was contacted or modified. Original C file pin values: `kernel/locking/rtmutex.c` = `36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9` and `kernel/futex.c` = `493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5`.

**Reproducible offline analyzer:** `HXL1-Stage3-v5-correlation.zip` delivered in chat. The contained `y2q_hxl1_stage3_member_attribution.py` and `y2q_hxl1_independent_opcode_audit.py` consume the existing exported ZIPs; no new REA or Ghidra invocation required. These two new modules have **not yet been committed** to this branch; the analysis remains separately packaged.
