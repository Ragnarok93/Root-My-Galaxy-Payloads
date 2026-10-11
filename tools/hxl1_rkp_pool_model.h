/* SPDX-License-Identifier: MIT
 * Offline HXL1 sparse RKP pool reference model, NOT a UH implementation.
 * Zero guest-memory writes. No assumed Samsung/Qualcomm physical carveout.
 */
#ifndef HXL1_RKP_POOL_MODEL_H
#define HXL1_RKP_POOL_MODEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HXL1_RKP_PAGE_BYTES UINT64_C(4096)
#define HXL1_RKP_SPARSE_UNIT_BYTES (UINT64_C(1) << 30)
#define HXL1_RKP_BITS_PER_UNIT (HXL1_RKP_SPARSE_UNIT_BYTES / HXL1_RKP_PAGE_BYTES)
#define HXL1_RKP_BITMAP_BYTES_PER_UNIT (HXL1_RKP_BITS_PER_UNIT / 8)
/* Avoid unbounded host allocations from malformed/hostile guest parameters. */
#define HXL1_RKP_MAX_UNITS 128U

typedef struct {
    uint64_t start; /* inclusive guest physical address */
    uint64_t end;   /* exclusive guest physical address */
} hxl1_rkp_range;

typedef struct {
    hxl1_rkp_range guest_ram;
    hxl1_rkp_range external_reservation;
    hxl1_rkp_range protected_pool;
    size_t sparse_units;
    size_t pool_pages;
    /* Host-side allocation state, distinct from pool-ownership bitmap. */
    uint8_t *allocated;
    /* One bit per RAM page: 1 indicates protected pool membership.
     * Map indexes are derived relative to guest_ram.start, not absolute PA. */
    uint8_t *owner_bitmap;
} hxl1_rkp_model;

typedef struct {
    uint64_t start_addr; /* original sparse_bitmap_for_kernel_t field 0 */
    uint64_t end_addr;   /* original field 1 */
    uint64_t maxn;       /* original field 2 */
    /* Guest char **map pointer is NOT populated by this offline model.
     * It requires a separately verified guest virtual-memory mapping. */
} hxl1_rkp_descriptor_metadata;

typedef enum {
    HXL1_RKP_OK = 0,
    HXL1_RKP_INVALID = 1,
    HXL1_RKP_OUT_OF_MEMORY = 2,
    HXL1_RKP_EXHAUSTED = 3,
    HXL1_RKP_NOT_ALLOCATED = 4
} hxl1_rkp_result;

hxl1_rkp_result hxl1_rkp_model_init(hxl1_rkp_model *m,
                                    hxl1_rkp_range ram,
                                    hxl1_rkp_range externally_reserved,
                                    hxl1_rkp_range pool);
void hxl1_rkp_model_destroy(hxl1_rkp_model *m);

/* Returns page-aligned physical address. Never writes guest memory or SMC X0. */
hxl1_rkp_result hxl1_rkp_alloc_pa(hxl1_rkp_model *m, uint64_t *pa);
hxl1_rkp_result hxl1_rkp_free_pa(hxl1_rkp_model *m, uint64_t pa);

/* Ownership is static across alloc/free, whereas allocation is dynamic. */
bool hxl1_rkp_is_owned_pa(const hxl1_rkp_model *m, uint64_t pa);
bool hxl1_rkp_is_allocated_pa(const hxl1_rkp_model *m, uint64_t pa);

/* Return a pointer to a host-only bit array for each 1GiB sparse unit. */
const uint8_t *hxl1_rkp_owner_unit(const hxl1_rkp_model *m, size_t unit);

/* Does not allocate guest addresses or create a usable guest descriptor. */
hxl1_rkp_descriptor_metadata hxl1_rkp_descriptor_fields(const hxl1_rkp_model *m);

#endif
