# HXL1 — GhostLock upstream extractor compatibility and evidence plan

**Status:** research-only, non-executable kernel profile.  
**Observed HXL1:** SM-G986U1 / G986U1UESCHXL1 / `4.19.113-27095354`; exact original SHA256-pinned `boot.img` v2 and extracted raw `kernel.bin`; recovered `vmlinux-stock.nm`; no raw BTF; no verified RT-mutex factory structure layouts; locked bootloader, enforced module signatures.

## Independent upstream audited

- Repository: https://github.com/YuKongA/ghostlock-app
- Reviewed upstream `main` at commit `9cdc4acbc283a1d1c84a3eb10379f7c9a960fb02` on 2026-10-10. Other similarly named forks may differ; do not conflate them.
- Documentation: `README.md`, `docs/kernel_profiles/README.md`, `docs/kernel_profiles/PROFILE_SCHEMA.md`.
- Code: `tools/extract_rs/src/boot.rs`, `main.rs`, `symbols.rs`, `kallsyms.rs`, `analysis.rs`, `fdt.rs`, and `tools/extract_rs/Cargo.toml`.

### Current compatibility facts

1. **Android boot image v2 unsupported:** the Rust `BootImage::from_android_boot` accepts only header versions 3/4. HXL1 `boot.img` has a *verified* v2 header; do not feed the v2 image and treat rejection as evidence the firmware is invalid. `BootImage::load` does accept raw arm64 Image input, so use **the original stock `kernel.bin`** instead.
2. **Kernel 4.19 HOCON profile generation blocked:** `main.rs` `--format conf` explicitly rejects releases whose major is neither 5 nor 6. Kernel layout verification in `symbols.rs` covers specified Android 5.15 and 6.x trains, **not 4.19**. A 4.19 runtime route/template and exact ABI are unverified.
3. **Read-only `--analysis` remains a useful independent experiment** and is deliberately distinct from `--format conf`. It identifies a detected kernel family and evaluates the `remove_waiter` primitive using a static disassembler heuristic. It does not establish CVE exploitation, reliable root, or KernelSU compatibility.
4. **Recovered `vmlinux-stock.nm` is a plausible `--kallsyms` input:** `kallsyms::parse` accepts `<8–16-digit hex address> <symbol type> <symbol name>` and requires nonzero `_text` or `_head`. Check the exact file rather than asserting parsing has succeeded.
5. **No raw BTF is present in the pinned HXL1 raw Image scan.** The extractor must not create fake factory `rt_mutex` / `rt_mutex_waiter` field offsets. The local corrected DWARF scan found zero complete definitions in 77 retained experimental objects.
6. **Bootloader XBL physical mapping not established:** upstream `fdt.rs` can inspect `xbl_config` FDT memory-map layouts on supported boot chains, but the original HXL1 BL `xbl_config.elf` has atypical ELF metadata, and neither it nor boot header `kernel_addr=0x8000` has yielded a verified Linux physical handoff. Do not use `--phys` to paper over this.
7. Upstream `Cargo.toml` specifies Rust `rust-version = 1.97.1`, and the binary lands in `build/extract/release/ghostlock-extract`. Record the upstream Git commit and binary hash for every attempt.

### Proposed strictly offline first pass (not executed by this report)

```bash
# Host-only research. No ADB, no profile registration, and no exploit execution.
git clone https://github.com/YuKongA/ghostlock-app.git ~/src/ghostlock-app-upstream
cd ~/src/ghostlock-app-upstream
git checkout 9cdc4acbc283a1d1c84a3eb10379f7c9a960fb02
rustc --version && cargo --version
cargo test --manifest-path tools/extract_rs/Cargo.toml
cargo build --release --manifest-path tools/extract_rs/Cargo.toml
mkdir -p ~/s20-artifacts/hxl1-research
build/extract/release/ghostlock-extract \
  ~/s20-artifacts/kernel.bin \
  --kallsyms ~/s20-artifacts/hxl1-research/vmlinux-stock.nm \
  --analysis \
  --out ~/s20-artifacts/hxl1-research/ghostlock-upstream-analysis.txt
```

The `--analysis` pass **must be classified as upstream heuristic results, not accepted port constants**. Do not use `--format conf`, `--allow-missing`, `--phys`, an imported .conf, or any GhostLock execution on this device at the present gate. If `cargo` or the parser fails, capture the host-side failure only and reconcile format assumptions before retrying.

### New XBL/GPU identity evidence (owner read-only results)

- Live KGSL `gpu_model: Adreno650v3`, corroborating the Adreno 650 family, but not directly proving candidate 1's `qcom,chipid = 0x6050002`.
- Original HXL1 `abl.elf` contains no matches for the owner's boot keyword scan at 5-character threshold.
- Original HXL1 `xbl.elf` contains `DefaultBDSBootApp = "LinuxLoader"` and `TZBSP_RTIC_DTB_NOT_INITIALIZED`. The latter **may** be related to the tiny fourth FDT's `qcom,rtic-id`, but this is only a shared RTIC/DTB terminology lead, not a proven reference or proof the structure is Linux's selected DTB.
- The `Kernel` memory-map string and `0xA0000000` constant shown in XBL **must not** be treated as a physical Linux load/handoff address without tracing their caller and relevant boot-stage meaning.

### Decision

Use GhostLock upstream source as an **independent analysis baseline**, not an executable 4.19 profile. Preserve existing Root-My-Galaxy-Payloads read-only tools for original firmware provenance and source/binary correlation. Stage 3 remains PARTIAL; Stage 4 OPEN; Stage 7 KernelSU BLOCKED; support feed disabled.
