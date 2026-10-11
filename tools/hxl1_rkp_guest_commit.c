/* SPDX-License-Identifier: MIT
 * Host-only / pluggable-backend RKP guest memory transaction.
 * No QEMU or guest I/O entrypoints are supplied by this component.
 */
#include "hxl1_rkp_guest_commit.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    hxl1_rkp_guest_mapping loc;
    const uint8_t *data;
    size_t size;
    uint8_t *original;
    bool attempted;
} commit_region;

static bool all_zero(const uint8_t *bytes, size_t len) {
    for (size_t i=0;i<len;i++) {
        if (bytes[i]!=0) return false;
    }
    return true;
}

static bool same(const uint8_t *left, const uint8_t *right, size_t len) {
    return memcmp(left,right,len)==0;
}

static void release_regions(commit_region *regions, size_t count) {
    for (size_t i=0;i<count;i++) {
        free(regions[i].original);
        regions[i].original=NULL;
    }
}

/* A failed write may have partially modified guest RAM. Undo in reverse
 * order, INCLUDING the failing region; verify each restored byte sequence.
 * Never silently hide an incomplete rollback.
 */
static bool restore_attempted(commit_region *regions, size_t count,
                              const hxl1_rkp_guest_backend *b, void *opaque,
                              uint8_t *readback, hxl1_rkp_commit_trace *trace) {
    bool ok=true;
    for (size_t n=count; n>0; --n) {
        commit_region *r=&regions[n-1];
        if (!r->attempted) continue;
        trace->rollbacks_attempted++;
        bool wrote=b->write_pa(opaque,r->loc.pa,r->original,r->size);
        bool read=false;
        if (wrote) {
            read=b->read_pa(opaque,r->loc.pa,readback,r->size);
        }
        if (!wrote || !read || !same(readback,r->original,r->size)) {
            ok=false;
        } else {
            trace->rollbacks_verified++;
        }
    }
    trace->rollback_complete=ok;
    trace->pointer_published=false;
    return ok;
}

hxl1_rkp_commit_status hxl1_rkp_guest_commit(
    const hxl1_rkp_model *model, const hxl1_rkp_guest_plan *plan,
    const hxl1_rkp_guest_backend *backend, void *opaque,
    hxl1_rkp_commit_trace *trace)
{
    if (!trace) return HXL1_RKP_COMMIT_BAD_ARGUMENT;
    memset(trace,0,sizeof(*trace));
    if (!model || !plan || !backend || !backend->verify_va_pa ||
        !backend->read_pa || !backend->write_pa) {
        return HXL1_RKP_COMMIT_BAD_ARGUMENT;
    }
    if (!backend->all_vcpus_quiesced || !backend->ram_reservation_verified) {
        return HXL1_RKP_COMMIT_PRECONDITION;
    }

    hxl1_rkp_guest_payload payload={0};
    hxl1_rkp_stage_status st=hxl1_rkp_guest_stage(
        model,plan,backend->verify_va_pa,opaque,&payload);
    if (st!=HXL1_RKP_STAGE_OK) {
        hxl1_rkp_guest_payload_destroy(&payload);
        if (st==HXL1_RKP_STAGE_UNVERIFIED_MAPPING) {
            return HXL1_RKP_COMMIT_MAPPING_UNVERIFIED;
        }
        if (st==HXL1_RKP_STAGE_OUT_OF_MEMORY) {
            return HXL1_RKP_COMMIT_OUT_OF_MEMORY;
        }
        return HXL1_RKP_COMMIT_BAD_ARGUMENT;
    }
    trace->mappings_verified=4;
    /* Global original kernel pointer is published LAST, after all other
     * guest structures are placed and independently read back.
     */
    commit_region regions[4]={
        {plan->bitmap_data,payload.bitmap_data,payload.bitmap_bytes,NULL,false},
        {plan->pointer_table,payload.pointer_table,payload.pointer_table_bytes,NULL,false},
        {plan->descriptor,payload.descriptor,sizeof(payload.descriptor),NULL,false},
        {plan->global_slot,payload.global_pointer,sizeof(payload.global_pointer),NULL,false}
    };
    hxl1_rkp_commit_status result=HXL1_RKP_COMMIT_OK;
    size_t maxsize=payload.bitmap_bytes;
    uint8_t *readback=malloc(maxsize);
    if (!readback) {
        result=HXL1_RKP_COMMIT_OUT_OF_MEMORY;
        goto done;
    }

    /* Snapshot everything BEFORE the first mutation. The destination must
     * be uninitialized; never replace existing guest memory contents.
     */
    for (size_t i=0;i<4;i++) {
        commit_region *r=&regions[i];
        if (!backend->verify_va_pa(opaque,r->loc.va,r->loc.pa,r->size,true)) {
            result=HXL1_RKP_COMMIT_MAPPING_UNVERIFIED;
            goto cleanup;
        }
        trace->mappings_verified++;
        r->original=malloc(r->size);
        if (!r->original) {
            result=HXL1_RKP_COMMIT_OUT_OF_MEMORY;
            goto cleanup;
        }
        if (!backend->read_pa(opaque,r->loc.pa,r->original,r->size)) {
            result=HXL1_RKP_COMMIT_SNAPSHOT_FAILED;
            goto cleanup;
        }
        trace->snapshots_read++;
        if (!all_zero(r->original,r->size)) {
            result=(i==3) ? HXL1_RKP_COMMIT_ALREADY_INITIALIZED :
                           HXL1_RKP_COMMIT_DIRTY_RESERVED_MEMORY;
            goto cleanup;
        }
    }

    for (size_t i=0;i<4;i++) {
        commit_region *r=&regions[i];
        if (!backend->verify_va_pa(opaque,r->loc.va,r->loc.pa,r->size,true)) {
            result=HXL1_RKP_COMMIT_MAPPING_UNVERIFIED;
            goto rollback;
        }
        trace->mappings_verified++;
        r->attempted=true; /* must cover partial writes */
        trace->writes_attempted++;
        if (!backend->write_pa(opaque,r->loc.pa,r->data,r->size) ||
            !backend->read_pa(opaque,r->loc.pa,readback,r->size) ||
            !same(readback,r->data,r->size)) {
            result=HXL1_RKP_COMMIT_WRITE_FAILED_ROLLED_BACK;
            goto rollback;
        }
        trace->writes_verified++;
        if (i==3) trace->pointer_published=true;
    }
    goto cleanup;

rollback:
    if (!restore_attempted(regions,4,backend,opaque,readback,trace)) {
        result=HXL1_RKP_COMMIT_ROLLBACK_FAILED;
    }
cleanup:
    free(readback);
done:
    release_regions(regions,4);
    hxl1_rkp_guest_payload_destroy(&payload);
    return result;
}
