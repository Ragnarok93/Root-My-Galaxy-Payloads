/* SPDX-License-Identifier: MIT
 * Stage original HXL1 sparse bitmap descriptor bytes in HOST-ONLY buffers.
 * Each guest mapping must be supplied and verified by an external adapter.
 */
#include "hxl1_rkp_guest_stage.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static bool bounded(uint64_t lo, uint64_t n) {
    return n != 0 && lo != 0 && lo <= UINT64_MAX - n;
}

static bool inside_mapping(hxl1_rkp_guest_mapping m, hxl1_rkp_range r) {
    return bounded(m.pa, m.size) && m.pa >= r.start &&
           m.pa + m.size <= r.end;
}

static bool overlaps(uint64_t a, uint64_t na, uint64_t b, uint64_t nb) {
    return a < b + nb && b < a + na;
}

static void store64(uint8_t *p, uint64_t val) {
    for (unsigned int b = 0; b < 8U; b++) {
        p[b] = (uint8_t)(val >> (8U * b));
    }
}

hxl1_rkp_stage_status hxl1_rkp_guest_stage(
    const hxl1_rkp_model *model,
    const hxl1_rkp_guest_plan *plan,
    hxl1_rkp_verify_mapping verify,
    void *opaque,
    hxl1_rkp_guest_payload *out)
{
    if (!model || !plan || !out || !verify || !model->owner_bitmap ||
        !model->allocated || !model->pool_pages ||
        !model->sparse_units || model->sparse_units > HXL1_RKP_MAX_UNITS) {
        return HXL1_RKP_STAGE_INVALID;
    }
    /* Caller must initialize payload to zero and explicitly destroy it. */
    if (out->pointer_table || out->bitmap_data) {
        return HXL1_RKP_STAGE_INVALID;
    }
    const uint64_t units = (uint64_t)model->sparse_units;
    const uint64_t table_size = units * UINT64_C(8);
    const uint64_t bitmap_size = units * HXL1_RKP_BITMAP_BYTES_PER_UNIT;

    const hxl1_rkp_guest_mapping maps[4] = {
        plan->global_slot, plan->descriptor, plan->pointer_table,
        plan->bitmap_data,
    };
    const uint64_t sizes[4] = {8, 32, table_size, bitmap_size};
    for (size_t i = 0; i < 4; i++) {
        if (maps[i].size != sizes[i] || !bounded(maps[i].va,maps[i].size) ||
            !bounded(maps[i].pa,maps[i].size) ||
            (maps[i].va % 8U)!=0 || (maps[i].pa % 8U)!=0) {
            return HXL1_RKP_STAGE_INVALID;
        }
        if (!inside_mapping(maps[i],model->guest_ram)) {
            return HXL1_RKP_STAGE_INVALID;
        }
        if (i == 0) {
            /* Target is original Linux .data global, never a UH page. */
            if (overlaps(maps[i].pa,maps[i].size,
                         model->external_reservation.start,
                         model->external_reservation.end -
                         model->external_reservation.start)) {
                return HXL1_RKP_STAGE_INVALID;
            }
        } else {
            if (!inside_mapping(maps[i],model->external_reservation) ||
                overlaps(maps[i].pa,maps[i].size,
                         model->protected_pool.start,
                         model->protected_pool.end-model->protected_pool.start)) {
                return HXL1_RKP_STAGE_INVALID;
            }
        }
        for (size_t j=0;j<i;j++) {
            if (overlaps(maps[i].pa,maps[i].size,
                         maps[j].pa,maps[j].size) ||
                overlaps(maps[i].va,maps[i].size,
                         maps[j].va,maps[j].size)) {
                return HXL1_RKP_STAGE_INVALID;
            }
        }
    }
    /* This callback is a REQUIRED external guest-MMU attestation; it may
     * not simply assume a universal linear kernel mapping. */
    for (size_t i=0;i<4;i++) {
        if (!verify(opaque,maps[i].va,maps[i].pa,maps[i].size,true)) {
            return HXL1_RKP_STAGE_UNVERIFIED_MAPPING;
        }
    }

    uint8_t *table=calloc((size_t)table_size,1);
    uint8_t *bitmap=calloc((size_t)bitmap_size,1);
    if (!table || !bitmap) {
        free(table);
        free(bitmap);
        return HXL1_RKP_STAGE_OUT_OF_MEMORY;
    }
    const hxl1_rkp_descriptor_metadata meta =
        hxl1_rkp_descriptor_fields(model);
    if (meta.maxn != units) {
        free(table);
        free(bitmap);
        return HXL1_RKP_STAGE_INVALID;
    }
    store64(out->global_pointer,plan->descriptor.va);
    store64(out->descriptor,meta.start_addr);
    store64(out->descriptor+8,meta.end_addr);
    store64(out->descriptor+16,meta.maxn);
    store64(out->descriptor+24,plan->pointer_table.va);
    for (size_t unit=0;unit<model->sparse_units;unit++) {
        store64(table+unit*8,
                plan->bitmap_data.va+
                (uint64_t)unit*HXL1_RKP_BITMAP_BYTES_PER_UNIT);
        const uint8_t *bits = hxl1_rkp_owner_unit(model,unit);
        if (!bits) {
            free(table);
            free(bitmap);
            memset(out,0,sizeof(*out));
            return HXL1_RKP_STAGE_INVALID;
        }
        memcpy(bitmap+unit*(size_t)HXL1_RKP_BITMAP_BYTES_PER_UNIT,
               bits,(size_t)HXL1_RKP_BITMAP_BYTES_PER_UNIT);
    }
    out->pointer_table=table;
    out->bitmap_data=bitmap;
    out->pointer_table_bytes=(size_t)table_size;
    out->bitmap_bytes=(size_t)bitmap_size;
    return HXL1_RKP_STAGE_OK;
}

void hxl1_rkp_guest_payload_destroy(hxl1_rkp_guest_payload *payload) {
    if (!payload) return;
    free(payload->pointer_table);
    free(payload->bitmap_data);
    memset(payload,0,sizeof(*payload));
}
