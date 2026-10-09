/*
 * Galaxy S20+ y2q HXL1 -- read-only research identity probe.
 * No root requests, device writes, exploit primitives or partition access.
 * Compile with Android NDK: aarch64-linux-android33-clang -O2 -Wall -Wextra
 *     identity_probe.c -o y2q-identity-probe
 */
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#else
#include <stdlib.h>
#endif

static const char *property(const char *name, char *buffer, size_t capacity) {
#ifdef __ANDROID__
    (void)capacity;
    int n = __system_property_get(name, buffer);
    if (n <= 0) buffer[0] = '\0';
#else
    const char *value = getenv(name);
    if (!value) value = "";
    snprintf(buffer, capacity, "%s", value);
#endif
    return buffer;
}

int main(void) {
    const char *keys[] = {
        "ro.product.model", "ro.product.device", "ro.boot.bootloader",
        "ro.build.fingerprint", "ro.build.version.security_patch",
        "ro.boot.flash.locked", "ro.boot.vbmeta.device_state"
    };
    char value[128];
    int mismatch = 0;
    struct utsname kernel;
    puts("Root My Galaxy -- y2q firmware identity probe (READ ONLY)");
    printf("uid=%ld; page_size=%ld\n", (long)getuid(), sysconf(_SC_PAGESIZE));
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *got = property(keys[i], value, sizeof(value));
        printf("%s=%s\n", keys[i], got);
        if (i == 0 && strcmp(got, "SM-G986U1") != 0) mismatch = 1;
        if (i == 1 && strcmp(got, "y2q") != 0) mismatch = 1;
        if (i == 2 && strcmp(got, "G986U1UESCHXL1") != 0) mismatch = 1;
        if (i == 3 && strcmp(got,
            "samsung/y2quew/y2q:13/TP1A.220624.014/G986U1UESCHXL1:user/release-keys") != 0)
            mismatch = 1;
    }
    if (uname(&kernel) < 0) {
        perror("uname");
        return 3;
    }
    printf("kernel.release=%s\n", kernel.release);
    if (strcmp(kernel.release, "4.19.113-27095354") != 0) mismatch = 1;
    if (mismatch) {
        fputs("RESULT=FIRMWARE_IDENTITY_MISMATCH\n", stderr);
        return 2;
    }
    puts("RESULT=FIRMWARE_IDENTITY_MATCH");
    puts("NOTE=Identity verification is not a root or vulnerability test.");
    return 0;
}
