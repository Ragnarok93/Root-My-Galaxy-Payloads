# HXL1 SM-G986U1 bootloader unlock: evidence-based route decision (2026-10-11)

Target: **SM-G986U1 XAA y2q / G986U1UESCHXL1**, US Snapdragon 865.
Purpose: evaluate a real, *bootable* unlock path, not merely a UI state flip, FRP bypass, forced software indicator, or write-to-flash.

## Existing project evidence

- Original BL SHA256: `f6048fb50cd83741951552866c4dcf26e6165b0a67a232b81028c266bef22d6b`.
- Original LinuxLoader EFI SHA256: `5e69a9718569fca1a13ccf5cecc5308619d459d4e796e7ec25fa090c06d99003`.
- Stock IsUnlocked byte at `0x351055` derives from normal-world persisted boot state, but the secure authorization to accept an unsigned image is **not established**.
- The OEM state initialized at `0x60af8` uses provider `0x60790` reading the last byte of partition `persistent`; `0x60918` handles a separate FRP-related value from offset `0x24`. This does **not** authenticate the OEM byte.
- LinuxLoader's direct request path uses `0x67dd8(4)`, reading bit 2 of `0x3651ec`, and dispatching to `0x34238` versus `0x34370`.
- `0x68d08` has source-attested writes to that bitmask following the EMC `BLGetStatus` response; its return codes, protected provenance and genuine privilege boundary are **not yet verified**.
- Device/kernel research has `CONFIG_MODULE_SIG_FORCE=y` and `CONFIG_KPROBES=n`; root via unrestricted stock kernel module insertion or Kprobe-based KernelSU is not currently a validated substitute for bootloader unlock.

## Routes evaluated

| Route | Evidence today | Release decision |
|---|---|---|
| Official US G986U1 OEM toggle / standard fastboot unlock | No authenticated OEM toggle/command support for the exact model; US Samsung Download Mode is not standard fastboot. | **NOT AVAILABLE / UNPROVEN** |
| Historical DID-bound unlock token + modified Odin | Historical paid unlock service documents per-device DID/token and firmware/bootloader limitations. No evidence an HXL1 binary-C / BL12 token can be obtained or accepted. | **UNVERIFIED FOR HXL1** |
| Stock OEM cached state `0x351055` or persistent last-byte change | Report/status state located, but missing secure authority and signed-image boot acceptance. | **INSUFFICIENT** |
| Modify global `0x3651ec` bit 2 or EMC response | Request dispatch path identified; no evidence of persistence, authenticated trust or legitimate unsigned image acceptance. | **INSUFFICIENT** |
| EDL Firehose / raw partition write | Public model-adjacent loaders exist, but signed loader acceptance, rollback constraints and image verification are separate gates. | **UNVERIFIED / HIGH BRICK RISK** |
| Crossflash Chinese/HK unlocked firmware `G9860` | Different model identity, trust policy and rollback; no demonstrated cross-acceptance by HXL1. | **DO NOT FLASH** |
| Isolated OEM stock-kernel privilege exploit | Investigated rt_mutex source resemblance, not a reproduced stock HXL1 privilege primitive; even root alone does not unlock boot verification. | **NOT DEMONSTRATED** |
| Obtain verifiably unlockable comparator device | Distinct physical model; may achieve root/payload goals but does not unlock this G986U1. | **VIABLE ALTERNATIVE HARDWARE** |

## Focused acceptance criteria for a *real* method

1. **Exact match** to SM-G986U1 with HXL1 / BL revision C (12), including actual device hardware state, not model-family claims.
2. **Authorized transition** established by device-native evidence (e.g. independently verifiable secure-state semantics / compatible per-device signed token), rather than assuming a writable Android flag or global memory byte.
3. **Distinct flash and next-boot gate verification**: prove the modified test boot image is accepted by Download Mode/flash authorization and by boot-time signature/rollback checks. They are two separate decisions.
4. **Recoverability / integrity plan** before any live test: matched original stock BL/AP/CP/CSC, signed restore path, partition backup feasibility, model/downgrade constraints, Knox, data wipe and brick risks.
5. **No unsupported claims** of unlock success until a reproducible real-device verification of lock state *and* boot of an accepted customized kernel/boot image.

## Highest-yield research next

A. Finish the bounded, source-pinned `0x365234` / `0x712b8` / `0x715e8` / `0x6d820` EMC response analysis already on branch; classify transaction status before interpreting as a security policy.
B. **Do not stay in this loop indefinitely.** Independently identify Download Mode custom-flash authorization and the earliest HXL1 secure component enforcing boot-image signature/rollback. If these are immutable without a valid token, an OEM status patch cannot achieve the goal.
C. Source-pin a *same-generation* unlocked comparator image **only when legitimately available** to compare trust-policy decision paths, not to crossflash onto US hardware.
D. Verify historical token route supports **specific BL C/12** with documented successful G986U1 HXL1 evidence before considering a purchase or flash.

## External context (not device confirmation)

- https://github.com/afaneh92/USACanadaSamsungBootloaderUnlock documents historical per-device DID/token workflow, modified Odin requirement, and firmware generation constraints.
- https://github.com/Alephgsm/SAMSUNG-EDL-Loaders lists a G986U-family Firehose path, **not** an HXL1 unlock guarantee.
- https://www.samsung.com/us/business/support/owners/product/galaxy-s20-plus-5g-unlocked/ is the *carrier-unlocked* US model support page; carrier-unlocked **does not mean bootloader-unlocked**.

**Conclusion: AS OF THIS DECISION THERE IS NO VERIFIED WORKING HXL1 BOOTLOADER UNLOCK METHOD.** Distinguish code-path discovery from authorization proof. No handset state was changed during this review.
