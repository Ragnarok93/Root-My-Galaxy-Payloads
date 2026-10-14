# HXL1 factory compiler-local attribution — evidence ceiling (2026-10-14)

**Scope:** offline inventory of owner-uploaded stock configuration and saved readelf/pahole reports, not a live exploit test or an original unstripped OEM `vmlinux`.

## Authenticated inputs and compiler settings

- `stock.config`, SHA-256 `ec6da4cfe412f7d0669c7d621751753375e32197a2602f98627eb95e71b9c0b2`.
- `abi-dwarf-audit.tar.gz`, SHA-256 `86b8b172c8f302ac7533da62449fcfbdada86c8b4d3bda34aab90318f84c0a97`.
- Exact stock config records `CONFIG_CC_IS_CLANG=y`, `CONFIG_CLANG_VERSION=100006` (Clang 10.0.6), `CONFIG_LTO_NONE=y`, `CONFIG_DEBUG_INFO=y`, `CONFIG_FRAME_POINTER=y`, `CONFIG_STACKPROTECTOR_STRONG=y`, `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_KPROBES=n`.

## Original vs comparison ELF debug availability

| Artifact | `.symtab` | `.debug_info` | `.BTF` | OEM compiler-local identity |
|---|---|---|---|---|
| Reconstructed stock HXL1 ELF | Present | **Absent** | **Absent** | **Not certifiable from this ELF** |
| QEMU normal ELF | Not assessed in this gate | Present | Not established by this gate | Not factory-equivalent |
| QEMU KASAN ELF | Not assessed in this gate | Present | Not established by this gate | Not factory-equivalent |

Both archived stock `pahole` queries for `task_struct` and `rt_mutex_waiter` failed (missing BTF / invalid argument). This does not imply the original OEM build lacked debug metadata. `CONFIG_DEBUG_INFO=y` shows debug generation was enabled, but the raw Image-to-ELF reconstruction preserves machine code and recovered names, **not missing original DWARF variable-location lists**.

Stock `CONFIG_LTO_NONE=y` removes **link-time optimization** as the default explanation for the missing recovered `futex_wait_requeue_pi` symbol. Per-translation-unit compiler inlining and other static optimizations still require independent source-to-machine evidence; there is no certified source local-object address/stack-slot mapping.

The two QEMU ELF debug records do not inherit stock ABI status. Their compiler and vendor Kconfig differences were already documented separately in the project's stock/QEMU comparison; DWARF there can establish rebuild layouts but not stock OEM local variables.

## Automated gate and tested outcome

`tools/y2q_hxl1_factory_debug_ceiling.py` requires SHA-pinned owner config, checks literal ELF-section inventories and archived stock `pahole` errors, and produces a JSON summary that fails closed if expected flags or debug-section availability change. Synthetic tests reject altered config, missing section tables, duplicate or symlink archive entries, and unsupported claims. **10/10 locally tested**, including the actual uploaded owner bundle. In GitHub CI the real-bundle test skips if the owner artifacts are absent; CI run completion has not yet been confirmed.

Generated local structured report SHA-256: `cb9a66c6a300d753895fccea96835c7f1825710dbf2c11b3c03bced4e8d94e05`.

## Next evidence, not another repeated pass

For *direct* OEM-compiled C-local attribution, the needed artifact is a firmware-build-matching **unstripped `vmlinux` or sidecar DWARF/`.dwo` debug symbols** with attributable OEM build provenance. Their absence from the *supplied/reconstructed* artifacts is an evidence availability gap, not proof that Samsung never generated them. Source compiler rebuilding can propose candidates but must be labeled comparison-only.

The original select buffer capacity, operation 11 switch path and source object-lifetime order are already recorded. None of these checks demonstrates physical cross-syscall stack reuse, temporary root, GhostLock exploitation, or KernelSU loading. Signed modules and Samsung hardening remain independent blocked/unverified acceptance gates.
