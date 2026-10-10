/*
 * RMG Galaxy S20+ HXL1: inert, read-only Android ARM64 probe library.
 *
 * Diagnostic candidate, NOT CVE-2026-43499 exploitation and NOT a root
 * payload. No constructors, futex racing, ioctl abuse, kernel-memory
 * operations, root requests, module loads or filesystem writes.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#else
#include <stdlib.h>
#endif

#define RMG_EXPORT __attribute__((visibility("default")))
#define RMG_MODEL "SM-G986U1"
#define RMG_DEVICE "y2q"
#define RMG_FIRMWARE "G986U1UESCHXL1"
#define RMG_FINGERPRINT "samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys"
#define RMG_RELEASE "4.19.113-27095354"

static int matches_property(const char *name, const char *expected) {
#ifdef __ANDROID__
    char actual[PROP_VALUE_MAX] = {0};
    int length = __system_property_get(name, actual);
    return length > 0 && strcmp(actual, expected) == 0;
#else
    const char *actual = getenv(name);
    return actual && strcmp(actual, expected) == 0;
#endif
}

/* Code 0 means firmware identity match ONLY, not vulnerability/root status.
 * Failure codes are stable and permit future app investigation integration. */
RMG_EXPORT int rmg_y2q_probe_status(void) {
    struct utsname kernel;
    if (!matches_property("ro.product.model", RMG_MODEL)) return 10;
    if (!matches_property("ro.product.device", RMG_DEVICE)) return 11;
    if (!matches_property("ro.boot.bootloader", RMG_FIRMWARE)) return 12;
    if (!matches_property("ro.build.fingerprint", RMG_FINGERPRINT)) return 13;
    if (!matches_property("ro.boot.flash.locked", "1")) return 14;
    if (!matches_property("ro.boot.vbmeta.device_state", "locked")) return 15;
    if (uname(&kernel) != 0 || strcmp(kernel.release, RMG_RELEASE) != 0) return 16;
    if (sysconf(_SC_PAGESIZE) != 4096) return 17;
    return 0;
}

RMG_EXPORT int rmg_y2q_probe_euid(void) {
    return (int)geteuid();
}

RMG_EXPORT const char *rmg_y2q_probe_firmware(void) {
    return RMG_FIRMWARE;
}

RMG_EXPORT const char *rmg_y2q_probe_kind(void) {
    return "read-only-firmware-identity-no-root";
}
