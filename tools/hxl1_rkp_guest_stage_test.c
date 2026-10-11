/* SPDX-License-Identifier: MIT
 * Synthetic guest-VA/PA fixtures. This does NOT verify a real QEMU MMU.
 */
#include "hxl1_rkp_guest_stage.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    hxl1_rkp_guest_plan expected;
    int call_count;
    int refuse_index;
} verifier_fixture;

static uint64_t ld64(const uint8_t *p) {
    uint64_t result = 0;
    for (int i=7; i>=0; i--) result=(result<<8) | p[i];
    return result;
}

static bool verify_fixture(void *ctx,uint64_t va,uint64_t pa,
                           uint64_t size,bool writable) {
    verifier_fixture *f=(verifier_fixture *)ctx;
    const hxl1_rkp_guest_mapping *rows[4] = {
        &f->expected.global_slot,&f->expected.descriptor,
        &f->expected.pointer_table,&f->expected.bitmap_data
    };
    const int i=f->call_count++;
    if (i >= 4 || i == f->refuse_index || !writable) return false;
    return rows[i]->va==va && rows[i]->pa==pa && rows[i]->size==size;
}

static hxl1_rkp_guest_plan good_plan(void) {
    hxl1_rkp_guest_plan p = {
        .global_slot = {0xffffff800a4dd0b8ULL,0x40002000ULL,8},
        .descriptor = {0xffffff800b000000ULL,0x60000000ULL,32},
        .pointer_table = {0xffffff800b001000ULL,0x60001000ULL,16},
        .bitmap_data = {0xffffff800b002000ULL,0x60002000ULL,65536}
    };
    return p;
}

static hxl1_rkp_model init_pool(void) {
    hxl1_rkp_model m={0};
    const hxl1_rkp_range ram={0x40000000ULL,0xc0000000ULL};
    const hxl1_rkp_range reserved={0x60000000ULL,0x60030000ULL};
    const hxl1_rkp_range pool={0x60020000ULL,0x60024000ULL};
    assert(hxl1_rkp_model_init(&m,ram,reserved,pool)==HXL1_RKP_OK);
    return m;
}

static void valid_staging(void) {
    hxl1_rkp_model m=init_pool();
    hxl1_rkp_guest_plan p=good_plan();
    verifier_fixture v={.expected=p,.refuse_index=-1};
    hxl1_rkp_guest_payload out={0};
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_OK);
    assert(v.call_count==4);
    assert(ld64(out.global_pointer)==p.descriptor.va);
    assert(ld64(out.descriptor)==0x40000000ULL);
    assert(ld64(out.descriptor+8)==0xc0000000ULL);
    assert(ld64(out.descriptor+16)==2);
    assert(ld64(out.descriptor+24)==p.pointer_table.va);
    assert(out.pointer_table_bytes==16);
    assert(out.bitmap_bytes==65536);
    assert(ld64(out.pointer_table)==p.bitmap_data.va);
    assert(ld64(out.pointer_table+8)==p.bitmap_data.va+32768);
    /* Pool page 0x60020000 belongs to sparse unit 0, offset 0x20020000. */
    const uint64_t bit=(0x60020000ULL-0x40000000ULL)/4096;
    assert((out.bitmap_data[bit>>3] & (1U<<(bit&7)))!=0);
    assert(out.bitmap_data[32768]==0); /* second 1GiB unit contains no pool */
    uint64_t pa=0;
    assert(hxl1_rkp_alloc_pa(&m,&pa)==HXL1_RKP_OK);
    /* Dynamic allocation does not mutate static membership bitmap. */
    assert((out.bitmap_data[bit>>3] & (1U<<(bit&7)))!=0);
    assert(hxl1_rkp_free_pa(&m,pa)==HXL1_RKP_OK);
    hxl1_rkp_guest_payload_destroy(&out);
    assert(!out.pointer_table && !out.bitmap_data && !out.bitmap_bytes);
    hxl1_rkp_model_destroy(&m);
}

static void mapping_rejected(void) {
    hxl1_rkp_model m=init_pool();
    hxl1_rkp_guest_plan p=good_plan();
    verifier_fixture v={.expected=p,.refuse_index=2};
    hxl1_rkp_guest_payload out={0};
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==
           HXL1_RKP_STAGE_UNVERIFIED_MAPPING);
    assert(out.pointer_table==NULL && out.bitmap_data==NULL);
    /* A verified mapping callback is mandatory, not an optional hook. */
    assert(hxl1_rkp_guest_stage(&m,&p,NULL,NULL,&out)==HXL1_RKP_STAGE_INVALID);
    hxl1_rkp_model_destroy(&m);
}

static void refuse_unreserved_or_overlapping(void) {
    hxl1_rkp_model m=init_pool();
    hxl1_rkp_guest_plan p=good_plan();
    hxl1_rkp_guest_payload out={0};
    verifier_fixture v={.expected=p,.refuse_index=-1};
    p.bitmap_data.pa=0x60021000ULL; /* inside protected pool */
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_INVALID);
    p=good_plan();
    p.bitmap_data.pa=0x60001000ULL; /* overlap pointer table */
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_INVALID);
    p=good_plan();
    p.global_slot.pa=0x60000000ULL; /* X2 must be original Linux global */
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_INVALID);
    p=good_plan();
    p.descriptor.va=p.pointer_table.va; /* alias unrelated guest pointers */
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_INVALID);
    p=good_plan();
    p.bitmap_data.size=65528; /* truncating one bitmap is not allowed */
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_INVALID);
    p=good_plan();
    p.global_slot.va=UINT64_MAX-3U; /* reject overflow and unaligned X2 */
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_INVALID);
    hxl1_rkp_model_destroy(&m);
}

static void staged_payload_must_be_destroyed(void) {
    hxl1_rkp_model m=init_pool();
    hxl1_rkp_guest_plan p=good_plan();
    verifier_fixture v={.expected=p,.refuse_index=-1};
    hxl1_rkp_guest_payload out={0};
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_OK);
    v.call_count=0;
    assert(hxl1_rkp_guest_stage(&m,&p,verify_fixture,&v,&out)==HXL1_RKP_STAGE_INVALID);
    hxl1_rkp_guest_payload_destroy(&out);
    hxl1_rkp_guest_payload_destroy(&out);
    hxl1_rkp_model_destroy(&m);
}

int main(int argc,char **argv) {
    if (argc!=2) return 2;
    if (strcmp(argv[1],"layout")==0) valid_staging();
    else if (strcmp(argv[1],"mapping")==0) mapping_rejected();
    else if (strcmp(argv[1],"safety")==0) refuse_unreserved_or_overlapping();
    else if (strcmp(argv[1],"lifetime")==0) staged_payload_must_be_destroyed();
    else return 3;
    printf("[PASS] HXL1 host-only descriptor staging %s\n",argv[1]);
    return 0;
}
