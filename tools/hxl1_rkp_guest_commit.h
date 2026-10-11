/* SPDX-License-Identifier: MIT
 * QEMU-neutral, host-tested transaction for staged HXL1 RKP bitmap bytes.
 * Backends are caller supplied: NOT a QEMU MMU, UH handler or RAM reservation.
 */
#ifndef HXL1_RKP_GUEST_COMMIT_H
#define HXL1_RKP_GUEST_COMMIT_H

#include "hxl1_rkp_guest_stage.h"

typedef bool (*hxl1_rkp_guest_read)(void *opaque, uint64_t pa,
                                    uint8_t *buf, size_t bytes);
typedef bool (*hxl1_rkp_guest_write)(void *opaque, uint64_t pa,
                                     const uint8_t *buf, size_t bytes);

typedef struct {
    hxl1_rkp_verify_mapping verify_va_pa;
    hxl1_rkp_guest_read read_pa;
    hxl1_rkp_guest_write write_pa;
    /* These are explicit preconditions; passing true DOES NOT prove them.
     * QEMU integration must independently verify a paused guest and
     * device-tree + memblock reservation before constructing this object.
     */
    bool all_vcpus_quiesced;
    bool ram_reservation_verified;
} hxl1_rkp_guest_backend;

typedef enum {
    HXL1_RKP_COMMIT_OK = 0,
    HXL1_RKP_COMMIT_BAD_ARGUMENT = 1,
    HXL1_RKP_COMMIT_PRECONDITION = 2,
    HXL1_RKP_COMMIT_MAPPING_UNVERIFIED = 3,
    HXL1_RKP_COMMIT_SNAPSHOT_FAILED = 4,
    HXL1_RKP_COMMIT_ALREADY_INITIALIZED = 5,
    HXL1_RKP_COMMIT_DIRTY_RESERVED_MEMORY = 6,
    HXL1_RKP_COMMIT_WRITE_FAILED_ROLLED_BACK = 7,
    HXL1_RKP_COMMIT_ROLLBACK_FAILED = 8,
    HXL1_RKP_COMMIT_OUT_OF_MEMORY = 9
} hxl1_rkp_commit_status;

typedef struct {
    unsigned int mappings_verified;
    unsigned int snapshots_read;
    unsigned int writes_attempted;
    unsigned int writes_verified;
    unsigned int rollbacks_attempted;
    unsigned int rollbacks_verified;
    bool pointer_published;
    bool rollback_complete;
} hxl1_rkp_commit_trace;

/* Stages bitmap (1), table (2), descriptor (3) and kernel global (4, LAST).
 * Reads/saves all four original buffers first. Requires empty protected
 * backing regions and an initially NULL original-kernel pointer. A failed
 * write or read-back triggers best-effort rollback and bytewise validation.
 * ROLLBACK_FAILED means guest RAM is untrusted: halt rather than continue.
 *
 * The backend may be a synthetic test fixture. This function alone NEVER
 * proves that RAM is reserved or that VA/PA mapping is correct.
 */
hxl1_rkp_commit_status hxl1_rkp_guest_commit(
    const hxl1_rkp_model *model, const hxl1_rkp_guest_plan *plan,
    const hxl1_rkp_guest_backend *backend, void *opaque,
    hxl1_rkp_commit_trace *trace);

#endif
