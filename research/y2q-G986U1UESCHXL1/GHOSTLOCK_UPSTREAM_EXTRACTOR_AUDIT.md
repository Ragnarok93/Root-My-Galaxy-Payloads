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
7. Upstream `Cargo.toml` specifies Rust `rust-version = 1.97.1`; the binary's actual path depends on Cargo configuration lookup. Record the upstream Git commit, `cargo metadata` target directory, and binary hash for every attempt.

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

## Owner WSL2 build attempt, 2026-10-10 — host toolchain gate only

- Successfully cloned the upstream repository and detached HEAD at audited `9cdc4acbc283a1d1c84a3eb10379f7c9a960fb02`.
- Host `rustc --version` and `cargo --version` both reported **1.75.0** (Ubuntu system toolchain).
- Both `cargo test --manifest-path tools/extract_rs/Cargo.toml` and `cargo build --release --manifest-path tools/extract_rs/Cargo.toml` stopped at manifest parsing: `feature edition2024 is required`.
- No binary was built; the subsequent extractor command exited **127** because `build/extract/release/ghostlock-extract` did not exist.
- **Classification:** `HOST_RUST_TOO_OLD` — not a GhostLock source compile failure, firmware format failure, primitive analysis, or 4.19 incompatibility verdict.
- Verified upstream `tools/extract_rs/Cargo.toml` requires `rust-version = "1.97.1"` and `edition = "2024"`. Rust 1.97.1 was officially published 2026-07-16 (https://blog.rust-lang.org/2026/07/16/Rust-1.97.1/).

**Next action:** install 1.97.1 with `rustup` alongside the system Rust, use `rustup run 1.97.1 cargo test` and `rustup run 1.97.1 cargo build --release` without changing the upstream manifest, then run the exact original `kernel.bin` + original `vmlinux-stock.nm` `--analysis` path with host-only logs. Do not infer vulnerability or physical addresses from a build passing.

## First completed upstream analysis and host `/proc/iomem` contamination — 2026-10-10

Owner built the extractor successfully using the Rust 1.97.1 toolchain. Running `cargo` with `--manifest-path` from the repository root put the binary in **`tools/extract_rs/target/release/ghostlock-extract`**, not `build/extract/release/` (the nested `.cargo/config.toml` was not in the active Cargo configuration search path). Prefer `cargo metadata --no-deps --format-version 1 --manifest-path ...` to locate the `target_directory` dynamically.

The Linux x86-64 ELF binary was verified with SHA256:
`aeab4c182a87711c817ae752d8e9b6414c30f33627bd02bd30fb05b1df5036b0`.

The owner's first run used the original raw HXL1 `kernel.bin`, original `vmlinux-stock.nm`, and `--analysis`, and returned exit code **0**, with:

- Release `4.19.113-27095354`; `kernel_family: unverified (no family layout will be emitted)`.
- No embedded BTF, no `rt_mutex_waiter` type, no measured `mm_struct` size.
- Static `remove_waiter@0xc7db4 unpatched` classifier; upstream `derive.rs` uses detection of an ARM64 `mrs ..., sp_el0` read in the disassembled function. This is **only a binary-pattern classifier**, corroborative of the original source comparison; it is **not** a demonstrated runtime CVE, validated exploit primitive, or root capability. An absent pattern should likewise not be mistaken for comprehensive patch verification.
- `multicast_waiter: available` because the upstream route checker accepts **either** `ip_mc_msfadd` or `ip_mc_source`; here `ip_mc_msfadd` was absent. `select_stack` appeared available at *symbol-presence* level; the select/pselect layout was **not attempted (no BTF)**. `tcp_zerocopy` was missing.
- **No suggested route** and **low confidence**. Do not take any `available` label as a working exploitation path.

### CRITICAL invalid physical load value

Upstream logged:

```text
info: iomem source /proc/iomem
info: iomem; kernel_phys_load=0xfffff800 kernel_phys_offset=0x0
kernel_phys_load        0xfffff800 (iomem)
```

This was an extractor **running inside WSL2**, which automatically read the **WSL2 host** `/proc/iomem`, combined its addresses with **Samsung kernel** `_text` / `_stext` symbols, and derived an invalid mixed-provenance quantity (upstream `main.rs` masks that subtraction to 32 bits). It is **NOT** the Galaxy S20+ physical Linux handoff, DRAM base, or a profile constant. Classify as **`INVALID_HOST_IOMEM_CONTAMINATION`**; Stage 4 remains **OPEN**.

Code verification: upstream `tools/extract_rs/src/iomem.rs::load` uses the host's `/proc/iomem` if `--iomem` is omitted. If `--iomem` is explicitly provided, it reads *only that path*, including an empty file; it does not fall back to host `/proc/iomem`.

### Host-only corrected offline rerun

```bash
cd ~/src/ghostlock-app-upstream
OUT="$HOME/s20-artifacts/hxl1-research"
mkdir -p "$OUT"
: > "$OUT/ghostlock-empty-host-iomem.txt"
BIN="$PWD/tools/extract_rs/target/release/ghostlock-extract"
"$BIN" "$HOME/s20-artifacts/kernel.bin" \
  --kallsyms "$OUT/vmlinux-stock.nm" \
  --iomem "$OUT/ghostlock-empty-host-iomem.txt" \
  --analysis \
  > "$OUT/ghostlock-upstream-analysis-isolated.txt" \
  2> "$OUT/ghostlock-upstream-diagnostics-isolated.txt"
echo "exit=$?"
cat "$OUT/ghostlock-upstream-analysis-isolated.txt"
cat "$OUT/ghostlock-upstream-diagnostics-isolated.txt"
```

Expected safe outcome: `kernel_phys_load` should remain **unset** (unless new legitimate, explicit device-side evidence is provided). If the isolated run still supplies a physical kernel address, stop and identify its source rather than accepting it. No `--phys`, built-in profile registration, runtime GhostLock invocation, or privilege elevation is authorized by this study.

## Owner's clean, host-isolated GhostLock analysis — 2026-10-10

The owner reran **the exact same** pinned-upstream extractor binary (`aeab4c182a87711c817ae752d8e9b6414c30f33627bd02bd30fb05b1df5036b0`, from the preceding verified build), original `kernel.bin`, and original `vmlinux-stock.nm`, explicitly passing a zero-byte `--iomem` file on WSL2.

**Exit status:** `0`. The resulting analysis and diagnostics are retained in the owner's local research directory as `ghostlock-upstream-analysis-isolated.txt` and `ghostlock-upstream-diagnostics-isolated.txt`.

```text
release                 4.19.113-27095354
kernel_major            4.19
kernel_family           unverified (no family layout will be emitted)
kernel_phys_load        unset (no xbl_config.img; pass --phys or let the runtime derive it)
rt_mutex_waiter         (no rt_mutex_waiter type in BTF)
mm_struct size          (unavailable)
primitive               remove_waiter@0xc7db4 unpatched
pselect chain           not attempted (no embedded BTF)
path multicast_waiter   available (ip_mc_msfadd=absent ip_mc_source@0xffffff800978367c)
path select_stack       available (core_sys_select@0xffffff80082f8d64 futex_wait@0xffffff80081900c4)
path tcp_zerocopy       missing (tcp_zerocopy_receive=absent)
suggested route         none (low)
```

Diagnostics: `CVE-2026-43499 primitive present (remove_waiter@0xc7db4 still uses current)`; `embedded BTF not found`; `4.19.113-27095354 is unverified; no family-derived geometry will be emitted`.

**Bounded interpretation:**
- **Host-address contamination resolved**; `kernel_phys_load` is now **unset**, as it should be. The earlier `0xfffff800` value remains *rejected* and must not be used for any subsequent research or profile.
- The static `remove_waiter` classifier corroborates the original, SHA256-pinned Samsung RT-mutex source's `current`/waiter ownership pattern. Upstream only checks an `mrs ..., sp_el0` disassembly signature; a match **cannot prove practical vulnerability reachability or a successful exploit**.
- The other route labels remain **symbol-presence checks**, not verified Linux 4.19 execution paths. `select_stack` stack geometry could not be assessed without BTF and `multicast_waiter` matched only `ip_mc_source` among two candidates.
- Stage 3 **PARTIAL**; Stage 4 **OPEN**; Stage 7 KernelSU **BLOCKED**; **no executable profile** and no app/support registration.

**Recommended next independent evidence step:** compare the upstream image-relative `remove_waiter` location against the recovered stock `vmlinux-stock.nm` `_text` and `remove_waiter` symbol delta. This checks the extractor's index/representation assumptions without suggesting a runtime address or executing the vulnerability. Preserve exact source and ELF/image provenance. Any mismatch is an artifact or parser problem requiring investigation, not evidence for a guessed adjustment.
