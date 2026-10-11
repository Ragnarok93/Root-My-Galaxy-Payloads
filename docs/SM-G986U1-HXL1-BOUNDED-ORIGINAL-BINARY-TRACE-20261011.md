# HXL1 — bounded original ARM64-word cleanup trace (2026-10-11)

## Authoritative input and local result

Owner-provided `HXL1-Stage3-Code-Slices.zip` and `HXL1-Stage3-REA-Evidence.zip` were available to the assistant. A **new offline constrained instruction interpreter** checked:

- Original HXL1 kernel SHA-256 represented in the successful owner-executed REA manifest: `ffbc90af676558557eb917687736c11f15b560dbb3cb9ca237224da5acb14123`.
- Whole REA isolated `remove_waiter` ELF SHA-256 `adca8a2187eb8dc7bcdbb1907d2a6881f7e3f0cac0354946eeb04b8646f4bd0d`.
- Exact 568-byte ELF executable section SHA-256 `f50dd6d1df275e0854e7d255c7f47abff81e2b065977e4a11b56007aa89d0c44`.
- Exact opcode bytes at 15 verified instruction positions in the *original Image-derived* slice from `remove_waiter+0x18` through `+0x6c` (including conditional control flow, synthetic current task pointer, and the `str xzr,[x20,#0x8f8]` store).

Controlled assumptions: cached top waiter is NULL; waiter rb entry is self-linked, current task and waiter task may differ, `MRS SP_EL0` reads a supplied synthetic task address, spin-lock helper calls are inert, and the interpreter stops before owner-priority-chain code. It begins after the ARM64 function prologue and does not attempt to emulate that prologue. The 15 executed original instruction words and branch choices were checked byte-for-byte against the pinned original code segment. There are no live syscalls, kernel calls, QEMU guest or hardware effects.

| Simulated object identity | `current.pi_blocked_on` | `waiter.task.pi_blocked_on` | Result |
|---|---|---|---|
| `current == waiter.task` | Cleared | Cleared (same object) | Expected |
| `current != waiter.task` | Cleared | Unchanged | Matches the previously reported ownership mismatch |

The factory instruction at `remove_waiter+0x68` is word `0xf9047e9f` / little-endian bytes `9f 7e 04 f9`. Both bounded cases and all **six focused negative/positive tests PASSED** in the assistant's isolated container (including tampering of the opcode and full isolated ELF digest, rejection of failed provenance, and no unsupported runtime/root flags).

**Precision:** this tool is `CONSTRAINED_ARM64_WORD_INTERPRETER_NOT_CPU_EMULATOR`. This is original factory **instruction byte interpretation**, *not* execution of the binary by an ARM64 CPU, QEMU user mode or full Samsung kernel. The C-fragment WSL execution at 12:50 UTC is independently confirmed as native host pass with an optional ARM64 QEMU user-mode skipped due to incomplete tools, not a failure of its native tests.

The working standalone verifier, six regression tests, frozen JSON output and full Markdown were packaged in `HXL1-bounded-original-ARM64-trace.zip` in the user conversation; this document records the findings, not a claim that the standalone Python code is checked into GitHub.

## What this does not prove

It does not reproduce the scheduler/PI race, on-device vulnerability, writable kernel primitive, bootloader unlock, full OEM compiled ABI, booted factory kernel, root or KernelSU. No HXL1 deployment authorization is implied. A source-faithful disposable Samsung kernel guest or independently verified permitted kernel-loading mechanism remains the consequential next gate. **Do not rerun REA or source-model tests solely to revisit this subgate.**
