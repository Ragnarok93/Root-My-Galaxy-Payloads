# Layout evidence correction

## Scope and provenance

This correction preserves the earlier observations from
`/home/main/ghidra_struct_results.json`. Those observations were **PARTIAL
candidates**, not verified structure layouts or approved build definitions.
This record is transcribed from the project owner's supplied evidence; the
original Linux artifacts were not reopened or executed in this update.

No firmware/model identity, kernel build identity, original artifact hashes,
or literal test output was supplied with this correction. Do not infer those
details or apply these candidates to existing device profiles.

## Preserved observations

| Definition or symbol | Recorded value | Evidence | Classification |
| --- | --- | --- | --- |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `0x0` | Matching name pointer | PARTIAL candidate; not a verified layout |
| `ASHMEM_MISC_FOPS_OFF` | `0x10` (16) | Matching operations pointer | PARTIAL candidate; not a verified layout |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `0x108` (264) | Matching pointer within the scanned table | PARTIAL table-symbol-relative displacement |
| `logger_array` | Symbol found; no member offset | Symbol lookup | Symbol evidence only |

**`0x108` was a displacement from the scanned table symbol. It is not
established as `offsetof(struct ctl_table, data)`.** A matching pointer or
symbol lookup alone does not establish the enclosing structure layout.

## Still unresolved

- `SELINUX_ENFORCING_OFF`
- `CONFIGFS_READ_ITER_OFF`
- `CONFIGFS_BIN_WRITE_ITER_OFF`
- `P0_PHYS_OFFSET`
- `P0_KERNEL_PHYS_LOAD`

The old fallback values **4, 16, 0, and 8 were guesses**, separate from the
observations above. The correction removes those guesses from consideration
as verified definitions without deleting the earlier evidence. No association
between individual guesses and unresolved definitions is inferred here.

The guessed fallback 16 and the independently observed `0x10` candidate must
not be conflated merely because their numeric values coincide.

## Previously recorded safety transaction

The owner reported reopening these four artifacts:

| Role | Recorded absolute path |
| --- | --- |
| MODIFIED_FILE | `/home/main/run-layout-safety-zrpmip61/Run.py` |
| DIFF_FILE | `/home/main/run-layout-safety-zrpmip61/changes.patch` |
| VERIFICATION | `/home/main/run-layout-safety-zrpmip61/VERIFICATION.txt` |
| ROLLBACK | `/home/main/run-layout-safety-zrpmip61/ROLLBACK.sh` |

Reported test outcomes:

- **BASELINE:** promoted candidates and permitted the mocked build.
- **MODIFIED:** blocked both candidate promotion and the mocked build.
- **ROLLBACK:** restored baseline behavior and pristine bytes.

These outcomes are historical reported evidence, not executions performed by
this repository update. A mocked build is not hardware validation, a real
payload build, or proof of a layout. The four paths are provenance references,
not repository-local files or downloadable attachments.

## Interpretation and release boundary

Retain partial observations as evidence, with their origin and uncertainty.
Do not promote them into verified offsets, fill unresolved fields with guesses,
or permit a build on the strength of this record. Independent, target-specific
layout and physical-address verification remains necessary before changing any
profile or release eligibility.

This documentation update does not modify runtime code, device profiles,
payload artifacts, support feeds, or their existing validation statuses. It
does not assert that the historical Run.py safety patch exists in either
repository.
