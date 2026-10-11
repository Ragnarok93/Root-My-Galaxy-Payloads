/* SPDX-License-Identifier: MIT
 * Offline serializer for a proposed HXL1 RKP sparse bitmap descriptor.
 * No QEMU/guest memory write, no fabricated guest VA->PA mapping or reservation.
 */
#ifndef HXL1_RKP_GUEST_STAGE_H
#define HXL1_RKP_GUEST_STAGE_H

#include "hxl1_rkp_pool_model.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Every mapping must be proven by a future emulator adapter's guest MMU.
 * The host-only test uses an explicitly fictional callback.
 */
typedef struct {
    uint64_t va;
    uint64_t pa;
    uint64_t size;
} hxl1_rkp_guest_mapping;

typedef struct {
    /* X2 is address of the original HXL1 kernel global POINTER slot. */
    hxl1_rkp_guest_mapping global_slot;
    /* Source's sparse_bitmap_for_kernel_t: 4 x LE64 = 32 bytes */
    hxl1_rkp_guest_mapping descriptor;
    /* char *map[maxn]: maxn x LE64 */
    hxl1_rkp_guest_mapping pointer_table;
    /* Exactly maxn x 32768 bytes */
    hxl1_rkp_guest_mapping bitmap_data;
} hxl1_rkp_guest_plan;

/* Adapter must verify mapped VA resolves to the PA, length and writable
 * backing from its *real* guest page tables / QEMU address space. In this
 * component the callback is only a self-contained test fixture.
 */
typedef bool (*hxl1_rkp_verify_mapping)(
    void *opaque, uint64_t va, uint64_t pa, uint64_t bytes, bool writable);

/* Output is a set of HOST-ONLY buffers. The adapter has to commit the three
 * reserved regions first and update global_slot only after all succeeded.
 * No rollback/transaction guarantees exist until an actual adapter is built.
 */
typedef struct {
    uint8_t global_pointer[8];
    uint8_t descriptor[32];
    uint8_t *pointer_table;
    uint8_t *bitmap_data;
    size_t pointer_table_bytes;
    size_t bitmap_bytes;
} hxl1_rkp_guest_payload;

typedef enum {
    HXL1_RKP_STAGE_OK=0,
    HXL1_RKP_STAGE_INVALID=1,
    HXL1_RKP_STAGE_UNVERIFIED_MAPPING=2,
    HXL1_RKP_STAGE_OUT_OF_MEMORY=3
} hxl1_rkp_stage_status;

hxl1_rkp_stage_status hxl1_rkp_guest_stage(
    const hxl1_rkp_model *model,
    const hxl1_rkp_guest_plan *plan,
    hxl1_rkp_verify_mapping verify,
    void *opaque,
    hxl1_rkp_guest_payload *out);

void hxl1_rkp_guest_payload_destroy(hxl1_rkp_guest_payload *payload);

#endif
