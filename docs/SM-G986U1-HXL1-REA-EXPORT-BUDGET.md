# Bounded REA export budget

The reviewed `Ragnarok93/rea` bridge blob
`ea1b8d2d60d66c8cedba5893dda38fb50c14559d` hard-codes a 3,000-operation
High P-code export ceiling and a 12,000-edge ceiling. The October 13 saved
`futex_lock_pi` dossier hits the operation ceiling. Native instructions match.

`tools/y2q_rea_export_budget.py` audits the exact reviewed Java source. With
`--apply`, it preserves the original in an exclusive backup and changes only
the operation and edge ceilings to 12,000 and 48,000. Unknown source revisions
are refused. An existing backup is never overwritten. The tool does not run
REA, rebuild its runtime, clear caches, or certify kernel fields.

```bash
cd ~/src/Root-My-Galaxy-Payloads
python3 tools/y2q_rea_export_budget.py --rea-root "$HOME/src/rea" --apply
```

Retain the receipt and backup. Verify that a fresh dossier actually exceeds
the former ceiling and reports no truncation before treating its graph as
complete. Increasing limits may increase processing time and JSON size. If
still truncated, retain the new result and inspect its counters.

The four undefined member comparisons remain separate work. This source budget
change does not create register-to-C-field proofs or change payload definitions.
