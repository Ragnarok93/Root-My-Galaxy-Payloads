/*
 * Root My Galaxy -- SM-G986U1 HXL1 futex-PI non-root capability smoke test.
 *
 * Ordinary, uncontended, single-thread FUTEX_WAIT/WAKE/LOCK_PI/TRYLOCK_PI/
 * UNLOCK_PI only. No PI requeue, contended locking, race loops, thread creation,
 * timing manipulation, tracing, module insertion, kernel writes or root calls.
 * This cannot establish CVE-2026-43499 exploitability or KernelSU readiness.
 *
 * RMG_HOST_TEST builds are for CI and cannot be built as Android diagnostics.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

#if defined(RMG_HOST_TEST) && defined(__ANDROID__)
#error "RMG_HOST_TEST must never be used for the Android device binary"
#endif
#if !defined(__aarch64__) && !defined(RMG_HOST_TEST)
#error "Device binary must target AArch64"
#endif

#define EXPECTED_MODEL "SM-G986U1"
#define EXPECTED_DEVICE "y2q"
#define EXPECTED_FIRMWARE "G986U1UESCHXL1"
#define EXPECTED_KERNEL "4.19.113-27095354"
#define EXPECTED_FINGERPRINT "samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys"

/* Always give all six syscall arguments, including unused NULL pointers. */
static int do_futex(uint32_t *word, int op, int value) {
    errno = 0;
    return (int)syscall(SYS_futex, word, op, value, NULL, NULL, 0);
}

static int check_identity(void) {
#ifdef RMG_HOST_TEST
    puts("IDENTITY=HOST_TEST_ONLY");
    return 0;
#elif defined(__ANDROID__)
    char value[PROP_VALUE_MAX] = {0};
    struct utsname uts;
    if (getuid() != 2000 || geteuid() != 2000) {
        puts("RESULT=REFUSED_NOT_ADB_SHELL");
        return 2;
    }
#define CHECK_PROP(prop, expected) do {                              \
    memset(value, 0, sizeof(value));                                \
    if (__system_property_get((prop), value) <= 0 ||                \
        strcmp(value, (expected)) != 0) {                           \
        printf("RESULT=REFUSED_IDENTITY_MISMATCH property=%s\n", (prop)); \
        return 2;                                                   \
    }                                                               \
} while (0)
    CHECK_PROP("ro.product.model", EXPECTED_MODEL);
    CHECK_PROP("ro.product.device", EXPECTED_DEVICE);
    CHECK_PROP("ro.boot.bootloader", EXPECTED_FIRMWARE);
    CHECK_PROP("ro.build.fingerprint", EXPECTED_FINGERPRINT);
    CHECK_PROP("ro.boot.flash.locked", "1");
    CHECK_PROP("ro.boot.vbmeta.device_state", "locked");
#undef CHECK_PROP
    if (uname(&uts) != 0 || strcmp(uts.release, EXPECTED_KERNEL) != 0 ||
        sysconf(_SC_PAGESIZE) != 4096) {
        puts("RESULT=REFUSED_KERNEL_IDENTITY_MISMATCH");
        return 2;
    }
    puts("IDENTITY=EXACT_STOCK_HXL1_ADB_SHELL");
    return 0;
#else
    puts("RESULT=REFUSED_NOT_ANDROID");
    return 2;
#endif
}

static int unavailable_errno(int err) {
    return err == ENOSYS || err == EPERM || err == EACCES ||
           err == EINVAL || err == EOPNOTSUPP;
}

/* Every PI word starts unlocked and is owned solely by this process/thread. */
static int pi_operation(const char *test, int lock_op) {
    uint32_t pi_word __attribute__((aligned(4))) = 0;
    const uint32_t tid = (uint32_t)syscall(SYS_gettid);
    int rc = do_futex(&pi_word, lock_op, 0);
    int error = (rc == -1) ? errno : 0;
    if (rc != 0) {
        printf("CHECK=%s STATUS=%s rc=%d errno=%d\n",
               test, unavailable_errno(error) ? "UNAVAILABLE" : "FAIL",
               rc, error);
        return unavailable_errno(error) ? 3 : 4;
    }

    /* Verify the uncontended lock reports this thread's owner TID. */
    uint32_t observed = __atomic_load_n(&pi_word, __ATOMIC_SEQ_CST);
    int valid_owner = (observed & FUTEX_TID_MASK) == tid;
    int unlock_rc = do_futex(&pi_word, FUTEX_UNLOCK_PI_PRIVATE, 0);
    int unlock_error = (unlock_rc == -1) ? errno : 0;
    uint32_t after = __atomic_load_n(&pi_word, __ATOMIC_SEQ_CST);
    printf("CHECK=%s STATUS=%s lock_rc=%d owner_matches=%d "
           "unlock_rc=%d unlock_errno=%d unlocked_zero=%d\n",
           test,
           (valid_owner && unlock_rc == 0 && after == 0) ? "PASS" : "FAIL",
           rc, valid_owner, unlock_rc, unlock_error, after == 0);
    return (valid_owner && unlock_rc == 0 && after == 0) ? 0 : 4;
}

static void describe(void) {
    puts("Root My Galaxy HXL1 — SAFE FUTEX PI SMOKE V1");
    puts("OPS=FUTEX_WAIT_PRIVATE(mismatch),FUTEX_WAKE_PRIVATE(empty),"
         "FUTEX_LOCK_PI_PRIVATE(uncontended),FUTEX_UNLOCK_PI_PRIVATE(owner),"
         "FUTEX_TRYLOCK_PI_PRIVATE(uncontended)");
    puts("NO=threads,contention,requeue,races,root,partition_writes,kernel_patches,BPF,modules");
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--describe") == 0) {
        describe();
        return 0;
    }
    if (argc != 1) {
        fprintf(stderr, "Usage: %s [--describe]\n", argv[0]);
        return 2;
    }
    describe();
    if (check_identity() != 0) return 2;

    uint32_t wait_word __attribute__((aligned(4))) = 1;
    int rc = do_futex(&wait_word, FUTEX_WAIT_PRIVATE, 0);
    int error = (rc == -1) ? errno : 0;
    int wait_ok = (rc == -1 && error == EAGAIN);
    printf("CHECK=WAIT_VALUE_MISMATCH STATUS=%s rc=%d errno=%d\n",
           wait_ok ? "PASS" : "FAIL", rc, error);

    rc = do_futex(&wait_word, FUTEX_WAKE_PRIVATE, 1);
    error = (rc == -1) ? errno : 0;
    int wake_ok = (rc == 0);
    printf("CHECK=WAKE_NO_WAITERS STATUS=%s rc=%d errno=%d\n",
           wake_ok ? "PASS" : "FAIL", rc, error);

    if (!wait_ok || !wake_ok) {
        puts("RESULT=FAIL_STANDARD_FUTEX");
        return 4;
    }

    /* Never initiate a contended lock, requeue operation or race. */
    int lock_result = pi_operation("LOCK_PI_UNCONTENDED", FUTEX_LOCK_PI_PRIVATE);
    int try_result = pi_operation("TRYLOCK_PI_UNCONTENDED", FUTEX_TRYLOCK_PI_PRIVATE);
    if (lock_result == 0 && try_result == 0) {
        puts("RESULT=PASS_BASIC_FUTEX_PI_SYSCALLS_ONLY");
        puts("NOTE=NOT_GHOSTLOCK_NOT_EXPLOIT_NOT_KERNELSU_NOT_ROOT");
        return 0;
    }
    if (lock_result == 3 || try_result == 3) {
        puts("RESULT=INCONCLUSIVE_PI_UNAVAILABLE");
        return 3;
    }
    puts("RESULT=FAIL_PI_SEMANTICS");
    return 4;
}
