# HXL1 stock Linux 4.19 — KernelSU module admission and hook capability checkpoint (October 14, 2026)

**Objective:** retain the [PORTING.md](PORTING.md) runtime GhostLock → temporary root → compatible KernelSU sequence on **SM-G986U1 / G986U1UESCHXL1 / Linux 4.19.113-27095354**. This is **only** the previously unresolved independent Stage 7 compatibility gate. This report does not replay RT-mutex, symbol, compiler, stack, or firmware inventories.

**Input:** the owner-supplied decompressed original `stock.config`, SHA-256 `ec6da4cfe412f7d0669c7d621751753375e32197a2602f98627eb95e71b9c0b2` (6,985 lines). **24 exact config assertions passed** in a read-only local check. This digest authenticates the supplied config bytes **not** an independent re-extraction from factory boot.img.

## New HXL1 finding — more than one loading/hook blocker

| Gate | Actual stock config evidence | Precise classification |
| --- | --- | --- |
| Linux module signing | `CONFIG_MODULE_SIG=y`, `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_MODULE_SIG_SHA512=y` | **Forced signature verification configured.** Neither an accepted key nor a trusted production-signed HXL1 KernelSU module has been proven. |
| **Samsung-specific module restriction (new)** | `CONFIG_UH=y`, `CONFIG_UH_RKP=y`, **`CONFIG_UH_LKM_BLOCK=y`** | **Additional vendor LKM-blocking configuration enabled.** Exact runtime policy decision and allowed/blocked module types are not established by the config alone. |
| Kprobe-based KernelSU hooks | **`CONFIG_KPROBES=n`** (despite `CONFIG_HAVE_KPROBES=y`) | **Unavailable in stock configuration.** Architecture support is not runtime registration support. |
| Function-tracer hook alternative | `CONFIG_FTRACE=y`; **`CONFIG_FUNCTION_TRACER=n`** | Generic ftrace does **not** establish function-entry tracer callbacks on HXL1. |
| Module infrastructure | `CONFIG_MODULES=y`, `CONFIG_MODULE_UNLOAD=y`, `CONFIG_MODVERSIONS=y`, `CONFIG_MODULE_FORCE_LOAD=n`, `CONFIG_ARM64_MODULE_PLTS=y` | Infrastructure exists; permission, matching kernel ABI/CRC, signatures and Samsung policy remain separate requirements. |
| Samsung protected state | `CONFIG_KDP_CRED=y`, `CONFIG_KDP_NS=y`, `CONFIG_KDP_DMAP=y`, `CONFIG_SECURITY_DEFEX=y` | Existing RMG 5.10/6.1/6.6 code cannot be assumed ABI- or KDP-compatible with HXL1 4.19. |
| Legacy filesystem dependency | `CONFIG_EXT4_FS=y` | Filesystem support is present, but it does not establish loading or hooks. |

**Where this changes the investigation:** Earlier notes correctly cited forced module signatures and disabled kprobes but omitted `CONFIG_UH_LKM_BLOCK=y` as a *separate* admission constraint, and did not distinguish generic ftrace from the disabled function tracer. The effective **stock LKM compatibility proof** therefore requires **both** accepted module admission under Samsung/Linux policies **and** an implemented 4.19 hook backend. Root privileges alone are not proof of either.

**External-reference scope:** [upstream KernelSU non-GKI integration notes](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md) are explicitly archived and state that current upstream does not officially support generic non-GKI kernels; they describe older source-level manual integration as an alternative to kprobes. They **do not certify** the customized RMG KernelSU v3.2.5 fork on Samsung 4.19. [Linux kprobe documentation](https://docs.kernel.org/trace/kprobes.html) likewise requires the real `CONFIG_KPROBES` feature.

**Consequences for the exact guide stages:** keep Stage 5 GhostLock runtime feasibility and Stage 7 KernelSU separate. A successfully built ARM64 `.ko`, available symbol name, acceptable `vermagic`, or hypothetical temporary root is insufficient evidence that stock HXL1 accepts or runs this KernelSU implementation. Source-integrated alternatives would also require independent **authorized bootable image** evidence, not available in this research. **No Stage 7 promotion.**

**Open proof obligations, not to be confused with completed checks:** (a) original runtime admission result for a trusted HXL1 module, (b) verified 4.19-compatible hook implementation, (c) compatibility with Samsung protected credentials/DEFEX, (d) signed-off device result. None is proven by the supplied stock config.

**No device accessed, no unsigned-module loading attempted, no firmware changed, and no privilege escalation or KernelSU installation demonstrated.**