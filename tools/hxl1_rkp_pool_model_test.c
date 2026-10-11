/* SPDX-License-Identifier: MIT
 * Synthetic host-only cases; never use these fictional ranges on a handset
 * or interpret passing fixtures as source-faithful HXL1 hardware emulation.
 */
#include "hxl1_rkp_pool_model.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static hxl1_rkp_range range(uint64_t a, uint64_t b) {
    hxl1_rkp_range r = {a, b};
    return r;
}
static hxl1_rkp_model blank(void) {
    hxl1_rkp_model m = {0};
    return m;
}

static void test_reserved_region_required(void) {
    hxl1_rkp_model m = blank();
    assert(hxl1_rkp_model_init(&m, range(0x40000000, 0xc0000000),
                                  range(0x80000000, 0x80010000),
                                  range(0x80020000, 0x80030000))
           == HXL1_RKP_INVALID);
    assert(m.owner_bitmap == NULL && m.allocated == NULL);
    assert(hxl1_rkp_model_init(&m, range(0x40000001, 0xc0000000),
                                  range(0x80000000, 0x80010000),
                                  range(0x80000000, 0x80010000))
           == HXL1_RKP_INVALID);
    assert(hxl1_rkp_model_init(&m, range(0x40000000, 0xc0000000),
                                  range(0xc0000000, 0xc0010000),
                                  range(0xc0000000, 0xc0001000))
           == HXL1_RKP_INVALID);
    hxl1_rkp_model_destroy(&m);
}
static void test_page_allocator_and_double_free(void) {
    hxl1_rkp_model m = blank();
    assert(hxl1_rkp_model_init(&m, range(0x40000000, 0xc0000000),
                                  range(0x80000000, 0x80010000),
                                  range(0x80001000, 0x80003000))
           == HXL1_RKP_OK);
    uint64_t a=0, b=0, c=42;
    assert(hxl1_rkp_alloc_pa(&m, &a) == HXL1_RKP_OK);
    assert(hxl1_rkp_alloc_pa(&m, &b) == HXL1_RKP_OK);
    assert(a == 0x80001000 && b == 0x80002000);
    assert(hxl1_rkp_is_allocated_pa(&m, a));
    assert(hxl1_rkp_alloc_pa(&m, &c) == HXL1_RKP_EXHAUSTED && c == 0);
    assert(hxl1_rkp_free_pa(&m, a) == HXL1_RKP_OK);
    assert(hxl1_rkp_free_pa(&m, a) == HXL1_RKP_NOT_ALLOCATED);
    assert(!hxl1_rkp_is_allocated_pa(&m, a));
    assert(hxl1_rkp_is_owned_pa(&m, a)); /* ownership does not disappear */
    assert(hxl1_rkp_alloc_pa(&m, &c) == HXL1_RKP_OK && c == a);
    assert(hxl1_rkp_free_pa(&m, b + 1) == HXL1_RKP_INVALID);
    assert(hxl1_rkp_free_pa(&m, 0x80004000) == HXL1_RKP_INVALID);
    hxl1_rkp_model_destroy(&m);
}
static void test_one_gib_sparse_crossing(void) {
    hxl1_rkp_model m = blank();
    assert(hxl1_rkp_model_init(&m, range(0x40000000, 0xc0000000),
                                  range(0x7fffe000, 0x80002000),
                                  range(0x7fffe000, 0x80002000))
           == HXL1_RKP_OK);
    assert(m.sparse_units == 2);
    assert(m.pool_pages == 4);
    assert(hxl1_rkp_is_owned_pa(&m, 0x7fffe000));
    assert(hxl1_rkp_is_owned_pa(&m, 0x7ffff000));
    assert(hxl1_rkp_is_owned_pa(&m, 0x80000000));
    assert(hxl1_rkp_is_owned_pa(&m, 0x80001000));
    assert(!hxl1_rkp_is_owned_pa(&m, 0x7fffd000));
    assert(!hxl1_rkp_is_owned_pa(&m, 0x80002000));
    const uint8_t *a=hxl1_rkp_owner_unit(&m,0);
    const uint8_t *b=hxl1_rkp_owner_unit(&m,1);
    assert(a != NULL && b != NULL);
    assert(a[HXL1_RKP_BITMAP_BYTES_PER_UNIT-1] == 0xc0);
    assert(b[0] == 0x03);
    assert(hxl1_rkp_owner_unit(&m,2) == NULL);
    const hxl1_rkp_descriptor_metadata d=hxl1_rkp_descriptor_fields(&m);
    assert(d.start_addr == 0x40000000 && d.end_addr == 0xc0000000);
    assert(d.maxn == 2);
    hxl1_rkp_model_destroy(&m);
}
static void test_bitmap_offsets_and_not_allocated(void) {
    hxl1_rkp_model m = blank();
    assert(hxl1_rkp_model_init(&m, range(0x40000000, 0xc0000000),
                                  range(0xa7000000, 0xa7100000),
                                  range(0xa7002000, 0xa7006000))
           == HXL1_RKP_OK);
    assert(!hxl1_rkp_is_owned_pa(&m, 0xa7001000));
    assert(hxl1_rkp_is_owned_pa(&m, 0xa7002000));
    assert(!hxl1_rkp_is_allocated_pa(&m, 0xa7002000));
    assert(!hxl1_rkp_is_owned_pa(&m, 0xa7002001));
    assert(!hxl1_rkp_is_owned_pa(&m, 0xc0000000));
    assert(hxl1_rkp_free_pa(&m, 0xa7002000) == HXL1_RKP_NOT_ALLOCATED);
    uint64_t pa;
    assert(hxl1_rkp_alloc_pa(&m,&pa) == HXL1_RKP_OK);
    assert(pa == 0xa7002000 && hxl1_rkp_is_allocated_pa(&m,pa));
    hxl1_rkp_model_destroy(&m);
}
static void test_bounded_inputs(void) {
    hxl1_rkp_model m=blank();
    assert(hxl1_rkp_model_init(&m,range(0x1000,0x4000000000),
                                 range(0x2000,0x4000),
                                 range(0x2000,0x3000)) == HXL1_RKP_INVALID);
    assert(hxl1_rkp_model_init(&m,range(0x0,0x100000000),
                                 range(0x0,0x60000000),
                                 range(0x0,0x60000000)) == HXL1_RKP_INVALID);
    assert(hxl1_rkp_alloc_pa(&m, NULL) == HXL1_RKP_INVALID);
    assert(hxl1_rkp_owner_unit(&m,0) == NULL);
    assert(hxl1_rkp_descriptor_fields(&m).maxn == 0);
    hxl1_rkp_model_destroy(&m);
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (strcmp(argv[1],"reservation") == 0) test_reserved_region_required();
    else if (strcmp(argv[1],"allocator") == 0) test_page_allocator_and_double_free();
    else if (strcmp(argv[1],"boundary") == 0) test_one_gib_sparse_crossing();
    else if (strcmp(argv[1],"bitmap") == 0) test_bitmap_offsets_and_not_allocated();
    else if (strcmp(argv[1],"limits") == 0) test_bounded_inputs();
    else return 3;
    printf("[PASS] host-only RKP %s\n",argv[1]);
    return 0;
}
