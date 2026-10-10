/*
 * Root My Galaxy / Y2Q: disposable ARM64 QEMU guest futex sanity diagnostic.
 *
 * Boot-only / bounded user-space syscalls: an immediate-return FUTEX_WAIT
 * mismatch, empty FUTEX_WAKE and two uncontended PI lock/unlock pairs.
 * Exactly one process/thread, no PI requeue, races, stalled waits,
 * privilege escalation, kernel patches, or CVE reproduction.
 * This is NOT a Samsung device image, kernel exploit or root payload.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <linux/futex.h>
#include <linux/reboot.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static void guest_poweroff(void) {
    sync();
    if (reboot(LINUX_REBOOT_CMD_POWER_OFF) != 0)
        printf("RMG_QEMU_LAB_WARN: poweroff errno=%d\n", errno);
    for (;;)
        pause();
}

static int futex_op(uint32_t *word, int command, int value) {
    errno = 0;
    return (int)syscall(SYS_futex, word, command, value, NULL, NULL, 0);
}

static int verify_pi_uncontended(const char *label, int lock_command) {
    uint32_t word __attribute__((aligned(4))) = 0;
    uint32_t tid = (uint32_t)syscall(SYS_gettid);
    int lock_rc = futex_op(&word, lock_command, 0);
    int lock_errno = lock_rc < 0 ? errno : 0;
    if (lock_rc != 0) {
        printf("RMG_QEMU_LAB_FAIL: %s lock_rc=%d errno=%d\n",
               label, lock_rc, lock_errno);
        return -1;
    }

    uint32_t observed = __atomic_load_n(&word, __ATOMIC_SEQ_CST);
    int owner_matches = ((observed & FUTEX_TID_MASK) == tid);
    int unlock_rc = futex_op(&word, FUTEX_UNLOCK_PI_PRIVATE, 0);
    int unlock_errno = unlock_rc < 0 ? errno : 0;
    uint32_t after = __atomic_load_n(&word, __ATOMIC_SEQ_CST);
    if (!owner_matches || unlock_rc != 0 || after != 0) {
        printf("RMG_QEMU_LAB_FAIL: %s owner_matches=%d unlock_rc=%d "
               "unlock_errno=%d unlocked_zero=%d\n",
               label, owner_matches, unlock_rc, unlock_errno, after == 0);
        return -1;
    }
    printf("RMG_QEMU_LAB_%s=PASS_UNCONTENDED\n", label);
    return 0;
}

int main(void) {
    struct utsname info;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("RMG_QEMU_LAB_BEGIN: isolated ARM64 VM, bounded futex-PI");
    if (getpid() != 1) {
        puts("RMG_QEMU_LAB_FAIL: guest diagnostic is not init/PID1");
        return 1;
    }
    if (uname(&info) != 0 || strcmp(info.machine, "aarch64") != 0) {
        puts("RMG_QEMU_LAB_FAIL: not AArch64");
        guest_poweroff();
    }
    printf("RMG_QEMU_LAB_KERNEL=%s\n", info.release);
    printf("RMG_QEMU_LAB_MACHINE=%s\n", info.machine);

    if (mount("proc", "/proc", "proc", 0, "") != 0)
        printf("RMG_QEMU_LAB_WARN: proc mount errno=%d\n", errno);
    if (mount("sysfs", "/sys", "sysfs", 0, "") != 0)
        printf("RMG_QEMU_LAB_WARN: sysfs mount errno=%d\n", errno);

    /* All following operations are single-threaded and nonblocking. */
    alarm(10);
    uint32_t wait_word __attribute__((aligned(4))) = 1;
    int ret = futex_op(&wait_word, FUTEX_WAIT_PRIVATE, 0);
    int wait_errno = ret < 0 ? errno : 0;
    if (ret != -1 || wait_errno != EAGAIN) {
        printf("RMG_QEMU_LAB_FAIL: basic futex errno=%d rc=%d\n",
               wait_errno, ret);
        guest_poweroff();
    }
    puts("RMG_QEMU_LAB_FUTEX=PASS_BASIC_WAIT_EAGAIN_ONLY");

    ret = futex_op(&wait_word, FUTEX_WAKE_PRIVATE, 1);
    int wake_errno = ret < 0 ? errno : 0;
    if (ret != 0) {
        printf("RMG_QEMU_LAB_FAIL: empty wake rc=%d errno=%d\n",
               ret, wake_errno);
        guest_poweroff();
    }
    puts("RMG_QEMU_LAB_FUTEX_WAKE=PASS_ZERO_WAITERS");

    if (verify_pi_uncontended("FUTEX_PI_LOCK",
                              FUTEX_LOCK_PI_PRIVATE) != 0 ||
        verify_pi_uncontended("FUTEX_PI_TRYLOCK",
                              FUTEX_TRYLOCK_PI_PRIVATE) != 0)
        guest_poweroff();

    alarm(0);
    puts("RMG_QEMU_LAB_COMPLETE=PASS_BOUNDED_PI_NOT_GHOSTLOCK");
    guest_poweroff();
}
