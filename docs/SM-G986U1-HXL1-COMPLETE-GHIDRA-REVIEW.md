# Complete saved Ghidra review, October 13

The uploaded `HXL1-complete-ghidra-results.tar.gz` was inspected directly.
The complete `futex_lock_pi` export retains 4,072 high P-code operations and
5,965 def-use links; no operations, inputs or edges are reported omitted.
All 723 native instruction records still match the previously attested archive.

The four previously undefined static comparisons are now implemented in
`y2q_hxl1_stage3_member_flow.py`: lock consistency, priority ordering,
conditional deadline ordering and the nested PI-node task-pointer candidate.
The task candidate explicitly uses the nested-node displacement; its memory
operand must not be mistaken for a direct waiter-base access. All 13 static
chains match the uploaded original provider records. They remain hypotheses
about C field identity, not path-complete alias proofs or factory DWARF.

The live reviewer now exposes decompiler warnings separately from export
completeness. `futex_lock_pi`'s terminal instruction is a call at the slice
boundary; the decompiler emits bad-data fallthrough there. An unmodeled
nonreturning callee is a plausible cause, not a proven callee identity. The
unsettled type-propagation and overlapping-global warnings remain unresolved.
No warnings are suppressed or treated as repaired by larger export limits.

Recheck retained files without invoking REA or rerunning prerequisites:

```bash
cd ~/src/Root-My-Galaxy-Payloads
python3 tools/y2q_hxl1_stage3_rea_live_review.py \
  --recheck-saved-live /home/main/s20-artifacts/hxl1-research/port-automation-20261013T074308981832Z/03-live-rea-ghidra/live-stage3-rea-review.json
```

This checks the retained isolated ELF hashes and provider input identities,
reuses the source-signature result from the saved report, and prints fresh
comparison classifications. It does not revalidate the unavailable full
factory kernel. Original files are not overwritten. An altered retained ELF
was rejected in verification. All 66 focused tests pass. Root, KernelSU and
factory member certification remain unverified.
