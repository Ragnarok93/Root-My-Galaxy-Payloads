# HXL1 — single-pass source + compiled-byte RT-mutex witness attestation

**Status:** research-only; original factory structure total sizes are not independently proven. This runnable check consumes previously exported evidence, **does not rerun REA/Ghidra**, flash, modify the phone, or compile the kernel.

The following new source files are committed on `feature/s20plus-investigation-shizuku-20261009`:

- `tools/y2q_hxl1_rtmutex_displacement_attest.py`
- `tools/test_y2q_hxl1_rtmutex_displacement_attest.py`

After `git pull --ff-only` in the existing checkout, run the following **single original-source attestation** (only needed because the unmodified Samsung checkout lives in the owner's WSL and cannot be read here):

```bash
cd ~/src/Root-My-Galaxy-Payloads
git pull --ff-only

python3 tools/y2q_hxl1_rtmutex_displacement_attest.py \
  --rea "$HOME/HXL1-Stage3-REA-Evidence.zip" \
  --slices "$HOME/HXL1-Stage3-Code-Slices.zip" \
  --source "$HOME/src/samsung-y2q-hxl1-stock" \
  --output "$HOME/s20-artifacts/hxl1-research/rtmutex-source-layout-attested.json"

python3 - <<'PY'
import json
from pathlib import Path
p=Path.home()/'s20-artifacts/hxl1-research/rtmutex-source-layout-attested.json'
r=json.loads(p.read_text())
print('[WITNESSES]',r['witnessCount'])
print('[ORIGINAL SOURCE CHECKED]',r['sourceProvenance']['sourceCOriginalPinsVerified'])
for name,entry in r['sourceProvenance']['originalSamsungHeaderDeclarationsFound'].items():
    print('[HEADER]',name,entry['originalHeaderSha256'],entry['declaredMemberOrder'],
          'conditional:',entry['conditionalMembersPossible'])
print('[FULL FACTORY TYPE LAYOUT]',r['fullFactoryStructLayoutsAuthenticated'])
PY
```

This checks the original `kernel/locking/rtmutex.c` and `kernel/futex.c` SHA-256 pins, identifies exact source header declarations and member order, hashes both headers, and separately authenticates 31 ARM64 instruction words with digests of the preserved original-Image-derived ELF slices.

**No report is emitted on failed original-source validation.** Failure may indicate the correct source tree isn't present, not a device flaw. Share the short stdout and (if needed) the error; do not rerun whole-kernel REA.

## Distinct proof boundaries

1. Original binary evidence: the 31 compiled ARM64 words and whole v4.2 ELF slice digests are authentic for this stock Image according to the owner-validated original Image provenance.
2. Original source evidence: the pinned Samsung checkout has the expected `rt_mutex` and `rt_mutex_waiter` declaration ordering; header hashes are recorded, not pre-guessed.
3. Remaining unproven facts: compiler configuration of any conditional members and full struct sizes, source-to-factory machine-code parity beyond the observed windows, live physical memory addresses, privilege-execution route, bootloader unlock and KernelSU installation.

**Gate:** Stage 3 remains PARTIAL even if the script passes. Passing is narrower than full factory-type-layout authentication.
