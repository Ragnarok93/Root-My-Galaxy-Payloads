/*
 * Root My Galaxy / Y2Q: disposable ARM64 QEMU guest boot-only diagnostic.
 * This is NOT an exploit, rooting payload, Samsung device kernel image, or
 * privilege-transition test. Built statically with aarch64-linux-gnu-gcc.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <linux/futex.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(void) {
    struct utsname info;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("RMG_QEMU_LAB_BEGIN: isolated ARM64 VM, boot-only diagnostics");
    if (getpid() != 1) {
        puts("RMG_QEMU_LAB_FAIL: guest diagnostic is not init/PID1");
        return 1;
    }
    if (uname(&info) != 0 || strcmp(info.machine, "aarch64") != 0) {
        puts("RMG_QEMU_LAB_FAIL: not AArch64");
        return 1;
    }
    printf("RMG_QEMU_LAB_KERNEL=%s\n", info.release);
    printf("RMG_QEMU_LAB_MACHINE=%s\n", info.machine);

    if (mount("proc", "/proc", "proc", 0, "") != 0)
        printf("RMG_QEMU_LAB_WARN: proc mount errno=%d\n", errno);
    if (mount("sysfs", "/sys", "sysfs", 0, "") != 0)
        printf("RMG_QEMU_LAB_WARN: sysfs mount errno=%d\n", errno);

    /* A single immediate-return WAIT mismatch, no PI requeue or contention. */
    uint32_t word __attribute__((aligned(4))) = 1;
    errno = 0;
    long ret = syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    if (ret != -1 || errno != EAGAIN) {
        printf("RMG_QEMU_LAB_FAIL: basic futex errno=%d ret=%ld\n", errno, ret);
        return 1;
    }
    puts("RMG_QEMU_LAB_FUTEX=PASS_BASIC_WAIT_EAGAIN_ONLY");
    puts("RMG_QEMU_LAB_COMPLETE=PASS_BOOT_ONLY_NOT_GHOSTLOCK");
    sync();
    if (reboot(LINUX_REBOOT_CMD_POWER_OFF) != 0)
        printf("RMG_QEMU_LAB_WARN: poweroff errno=%d\n", errno);
    /* If QEMU lacks a poweroff device, halt the user-space task. */
    for (;;)
        pause();
}
