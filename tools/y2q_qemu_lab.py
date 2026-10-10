#!/usr/bin/env python3
"""Disposable, boot-only Linux 4.19 ARM64 QEMU laboratory for Root My Galaxy.

No Android device / ADB / boot partition access. No CVE exploit, PI requeue,
kernel modification, module injection, or privilege escalation.

Prerequisites:
    sudo apt install qemu-system-arm bc bison flex libssl-dev libelf-dev
    # Existing user tools: aarch64-linux-gnu-gcc, make, git
    # Obtain official upstream linux-4.19.325 source separately (NOT Samsung).

WSL commands:
    python3 tools/y2q_qemu_lab.py check
    python3 tools/y2q_qemu_lab.py initramfs
    python3 tools/y2q_qemu_lab.py configure
    python3 tools/y2q_qemu_lab.py build
    python3 tools/y2q_qemu_lab.py boot

'configure --kasan' requests KASAN and RT-mutex debugging, validating the
resulting .config. Keep the default boot-only pass before enabling KASAN.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GUEST_SOURCE = ROOT / "research/y2q-G986U1UESCHXL1/qemu_lab_init.c"
DEFAULT_SOURCE = Path.home() / "src/linux-4.19.325"
DEFAULT_VENDOR = Path.home() / "src/samsung-y2q-hxl1-stock"
DEFAULT_OUTPUT = Path.home() / "s20-artifacts/qemu-lab"
UPSTREAM_URL = "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.19.325.tar.xz"
VENDOR_HASHES = {
    "kernel/locking/rtmutex.c": "36b187173cfb3934a5c9d51952bce58c2f41701d3585326f18cd3965e46a21f9",
    "kernel/futex.c": "493565da491190d11cf023841128872c07799ddc786b708e3eb4f3130c9894a5",
}
REQUIRED_TOOLS = (
    "qemu-system-aarch64", "aarch64-linux-gnu-gcc", "make", "cpio",
    "bc", "bison", "flex", "git",
)


class LabError(Exception):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as file:
        for part in iter(lambda: file.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def check_vendor(source: Path) -> dict[str, bool | str]:
    results: dict[str, bool | str] = {}
    for relative, expected in VENDOR_HASHES.items():
        file = source / relative
        results[relative] = file.is_file() and sha256(file) == expected
    results["allMatch"] = all(v is True for v in results.values())
    return results


def check_kernel_source(source: Path, vendor: Path) -> None:
    if not source.is_dir():
        raise LabError(
            f"Upstream 4.19 source not found: {source}\n"
            f"Obtain the official archive from {UPSTREAM_URL}, extract "
            f"to {source}, then rerun. Do NOT use the Samsung source tree."
        )
    if source.resolve() == vendor.resolve():
        raise LabError("Refusing to build vendor stock source as QEMU virt kernel")
    mk = source / "Makefile"
    if not mk.is_file():
        raise LabError(f"Linux kernel Makefile not found: {mk}")
    lines = mk.read_text(encoding="utf-8", errors="replace").splitlines()[:24]
    items = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            items[k.strip()] = v.strip()
    if items.get("VERSION") != "4" or items.get("PATCHLEVEL") != "19":
        raise LabError("Only upstream Linux 4.19 is allowed in this lab")
    if not (source / "arch/arm64/configs/defconfig").is_file():
        raise LabError("Source lacks ARM64 default configuration")
    rt = source / "kernel/locking/rtmutex.c"
    if rt.is_file() and sha256(rt) == VENDOR_HASHES["kernel/locking/rtmutex.c"]:
        raise LabError("Source appears to contain the original Samsung vendor RT-mutex")
    if not (source / "kernel/futex.c").is_file():
        raise LabError("Source lacks kernel/futex.c")


def check_tools() -> dict[str, str | None]:
    return {tool: shutil.which(tool) for tool in REQUIRED_TOOLS}


def check(args: argparse.Namespace) -> int:
    print("RMG / ARM64 QEMU / BOOT-ONLY OFFLINE LAB\n")
    for name, location in check_tools().items():
        print(f"[{'OK' if location else 'MISSING'}] {name}: {location or 'not installed'}")
    try:
        kernel_version = (
            args.source / "Makefile"
        ).read_text(encoding="utf-8").splitlines()[0]
        print(f"Upstream source: {args.source} ({kernel_version})")
    except OSError:
        print(f"Upstream source: MISSING ({args.source})")
        print(f"Official archive: {UPSTREAM_URL}")
    integrity = check_vendor(args.vendor)
    print(f"Original vendor source matches: {integrity['allMatch']}")
    for name, result in integrity.items():
        if name != "allMatch":
            print(f"  {name}: {'PASS' if result else 'NOT VERIFIED'}")
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text().splitlines():
            if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:")):
                print(line)
    return 0 if all(check_tools().values()) and integrity["allMatch"] else 2


def write_cpio(entries: list[tuple[str, bytes, int, int, int]]) -> bytes:
    """Create a minimal reproducible cpio newc archive, without root or mknod."""
    archive = bytearray()
    for ino, (name, data, mode, rmajor, rminor) in enumerate(entries, 1):
        if not name or name.startswith("/") or ".." in Path(name).parts:
            raise LabError(f"Unsafe CPIO entry name: {name!r}")
        namebytes = name.encode("utf-8") + b"\x00"
        numbers = (
            ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0,
            len(data), 0, 0, rmajor, rminor, len(namebytes), 0
        )
        archive.extend(b"070701")
        archive.extend("".join(f"{number:08x}" for number in numbers).encode("ascii"))
        archive.extend(namebytes)
        archive.extend(b"\x00" * ((-len(archive)) % 4))
        archive.extend(data)
        archive.extend(b"\x00" * ((-len(archive)) % 4))
    return bytes(archive)


def make_initramfs(args: argparse.Namespace) -> Path:
    compiler = shutil.which("aarch64-linux-gnu-gcc")
    if not compiler:
        raise LabError("Missing aarch64-linux-gnu-gcc")
    args.output.mkdir(parents=True, exist_ok=True)
    guest = args.output / "init"
    cmd = [
        compiler, "-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-fstack-protector-strong", str(GUEST_SOURCE), "-o", str(guest),
    ]
    print("+", " ".join(cmd), flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=100)
    if result.returncode:
        raise LabError(f"Guest build failed:\n{result.stderr[-2500:]}")
    with guest.open("rb") as file:
        elf = file.read(20)
    if elf[:6] != b"\x7fELF\x02\x01" or int.from_bytes(elf[18:20], "little") != 183:
        raise LabError("Guest /init is not 64-bit AArch64 ELF")
    payload = guest.read_bytes()
    root_dirs = [
        (name, b"", stat.S_IFDIR | 0o755, 0, 0)
        for name in ("dev", "proc", "sys")
    ]
    root_devices = [
        ("dev/console", b"", stat.S_IFCHR | 0o600, 5, 1),
        ("dev/null", b"", stat.S_IFCHR | 0o666, 1, 3),
    ]
    entries = root_dirs + root_devices + [
        ("init", payload, stat.S_IFREG | 0o755, 0, 0),
        ("TRAILER!!!", b"", 0, 0, 0)
    ]
    archive = args.output / "initramfs.cpio.gz"
    with archive.open("wb") as out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
            gz.write(write_cpio(entries))
    print(f"[OK] Standalone aarch64 guest init: {guest} (sha256 {sha256(guest)})")
    print(f"[OK] Disposable initramfs: {archive} (sha256 {sha256(archive)})")
    return archive


def kernel_args(args: argparse.Namespace) -> list[str]:
    return [
        "make", "-C", str(args.source), f"O={args.output / 'kernel-build'}",
        "ARCH=arm64", "CROSS_COMPILE=aarch64-linux-gnu-",
    ]


def configure(args: argparse.Namespace) -> None:
    check_kernel_source(args.source, args.vendor)
    for t in ("make", "aarch64-linux-gnu-gcc"):
        if not shutil.which(t):
            raise LabError(f"Missing build tool: {t}")
    args.output.mkdir(parents=True, exist_ok=True)
    base = kernel_args(args)
    subprocess.run(base + ["defconfig"], check=True)
    config = args.output / "kernel-build/.config"
    script = args.source / "scripts/config"
    flags = [
        "-e", "BLK_DEV_INITRD", "-e", "DEVTMPFS", "-e", "DEVTMPFS_MOUNT",
        "-e", "TMPFS", "-e", "SERIAL_AMBA_PL011",
        "-e", "SERIAL_AMBA_PL011_CONSOLE", "-e", "FUTEX",
    ]
    if args.kasan:
        flags += [
            "-e", "KASAN", "-e", "KASAN_OUTLINE",
            "-d", "KASAN_INLINE", "-e", "DEBUG_RT_MUTEXES",
            "-e", "DEBUG_LIST", "-e", "DEBUG_SPINLOCK",
        ]
    subprocess.run([str(script), "--file", str(config)] + flags, check=True)
    subprocess.run(base + ["olddefconfig"], check=True)
    content = config.read_text()
    required = ["CONFIG_BLK_DEV_INITRD=y", "CONFIG_SERIAL_AMBA_PL011_CONSOLE=y",
                "CONFIG_FUTEX=y"]
    if args.kasan:
        required += ["CONFIG_KASAN=y", "CONFIG_DEBUG_RT_MUTEXES=y"]
    missing = [x for x in required if x not in content.splitlines()]
    if missing:
        raise LabError(f"Kernel configuration declined required options: {missing}")
    (args.output / "lab-config.json").write_text(
        json.dumps({
            "source": str(args.source.resolve()), "configSha256": sha256(config),
            "kasan": args.kasan, "buildJobsMax": 2,
            "scope": "upstream Linux 4.19 QEMU lab only; not Samsung kernel"
        }, indent=2) + "\n"
    )
    print(f"[OK] Lab kernel configured: {config}")
    print(f"     KASAN requested: {args.kasan}")


def build(args: argparse.Namespace) -> None:
    check_kernel_source(args.source, args.vendor)
    if not (args.output / "kernel-build/.config").is_file():
        raise LabError("Kernel not configured. Run 'configure' first.")
    if args.jobs not in (1, 2):
        raise LabError("Host RAM is limited: select only --jobs 1 or 2")
    args.output.mkdir(parents=True, exist_ok=True)
    log = args.output / "kernel-build.log"
    cmd = kernel_args(args) + [f"-j{args.jobs}", "Image"]
    print("+", " ".join(cmd), flush=True)
    print(f"[log] {log} (build output captured to avoid console flooding)")
    with log.open("w") as stream:
        result = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        excerpt = "\n".join(log.read_text(errors="replace").splitlines()[-35:])
        raise LabError(f"Kernel build failed ({result.returncode}). Last lines:\n{excerpt}")
    image = args.output / "kernel-build/arch/arm64/boot/Image"
    if not image.is_file():
        raise LabError("Build returned success but ARM64 Image is missing")
    print(f"[OK] {image} (sha256 {sha256(image)})")


def boot(args: argparse.Namespace) -> int:
    image = args.output / "kernel-build/arch/arm64/boot/Image"
    ramdisk = args.output / "initramfs.cpio.gz"
    if not image.is_file() or not ramdisk.is_file():
        raise LabError("Missing kernel Image or initramfs; run initramfs/configure/build")
    if not shutil.which("qemu-system-aarch64"):
        raise LabError("Install the Ubuntu 'qemu-system-arm' package first")
    cmd = [
        "qemu-system-aarch64",
        "-machine", "virt", "-cpu", "cortex-a57", "-smp", "1",
        "-m", str(args.memory),
        "-kernel", str(image), "-initrd", str(ramdisk),
        "-append", "console=ttyAMA0 rdinit=/init loglevel=6 panic=-1",
        "-nographic", "-monitor", "none",
        "-no-reboot", "-nic", "none",
    ]
    print("+", " ".join(cmd), flush=True)
    args.output.mkdir(parents=True, exist_ok=True)
    timed_out = False
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             errors="replace", timeout=args.timeout)
        trace = res.stdout + res.stderr
        rc = res.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        trace = (
            (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes)
            else exc.stdout or ""
        )
        rc = -1
    passed = "RMG_QEMU_LAB_COMPLETE=PASS_BOOT_ONLY_NOT_GHOSTLOCK" in trace
    fatal = any(marker in trace for marker in
                ("Kernel panic", "RMG_QEMU_LAB_FAIL", "BUG: KASAN:", "Oops:"))
    status = "PASS_BOOT_ONLY" if passed and not fatal else (
        "INCONCLUSIVE_TIMEOUT" if timed_out else "FAIL_BOOT"
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log = args.output / f"qemu-boot-{stamp}.log"
    log.write_text(trace)
    report = args.output / f"qemu-boot-{stamp}.json"
    report.write_text(json.dumps({
        "status": status, "returnCode": rc, "timedOut": timed_out,
        "memoryMiB": args.memory, "cpus": 1,
        "guestKernelSha256": sha256(image), "initramfsSha256": sha256(ramdisk),
        "scope": "Upstream Linux 4.19 VM boot and immediate-return futex only",
        "stockSamsungDeviceAffected": False, "ghostLockReproduced": False,
        "kernelSuValidated": False, "rootOnPhoneVerified": False
    }, indent=2) + "\n")
    print("\n".join(trace.splitlines()[-25:]))
    print(f"[{status}] Logs: {log}  Report: {report}")
    return 0 if status == "PASS_BOOT_ONLY" else 3


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("check", "initramfs", "configure", "build", "boot"))
    p.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    p.add_argument("--vendor", type=Path, default=DEFAULT_VENDOR)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--kasan", action="store_true",
                   help="On configure only: request KASAN/debug RT-mutex options")
    p.add_argument("--jobs", type=int, default=1, choices=(1, 2))
    p.add_argument("--memory", type=int, default=1024,
                   help="QEMU RAM MiB; start with 1024; use 1536 for KASAN")
    p.add_argument("--timeout", type=int, default=240,
                   help="Guest emulation timeout in seconds")
    args = p.parse_args()
    args.source = args.source.expanduser().resolve()
    args.vendor = args.vendor.expanduser().resolve()
    args.output = args.output.expanduser().resolve()
    if args.memory < 768 or args.memory > 1536:
        p.error("--memory must be between 768 and 1536 MiB on this WSL host")
    if args.timeout < 30 or args.timeout > 900:
        p.error("--timeout must be 30..900s")
    if args.kasan and args.action != "configure":
        p.error("--kasan is only valid with 'configure'")
    try:
        if args.action == "check":
            return check(args)
        if args.action == "initramfs":
            make_initramfs(args)
        elif args.action == "configure":
            configure(args)
        elif args.action == "build":
            build(args)
        else:
            return boot(args)
        return 0
    except (LabError, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f"[STOP] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
