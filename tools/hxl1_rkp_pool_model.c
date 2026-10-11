/* SPDX-License-Identifier: MIT
 * Offline HXL1 RKP sparse ownership and protected-pool allocation model.
 * This is NOT a security hypervisor, QEMU plugin, or guest-memory adapter.
 */
#include "hxl1_rkp_pool_model.h"

#include <stdlib.h>
#include <string.h>

#define MAX_POOL_PAGES (UINT64_C(1) << 18) /* 1GiB maximum fixture pool */

static bool valid_range(hxl1_rkp_range a) {
    return a.start < a.end && (a.start % HXL1_RKP_PAGE_BYTES) == 0 &&
           (a.end % HXL1_RKP_PAGE_BYTES) == 0;
}

static bool inside(hxl1_rkp_range inner, hxl1_rkp_range outer) {
    return inner.start >= outer.start && inner.end <= outer.end;
}

static bool test_bit(const uint8_t *map, size_t idx) {
    return (map[idx >> 3] & (uint8_t)(1U << (idx & 7U))) != 0;
}

static void set_bit(uint8_t *map, size_t idx) {
    map[idx >> 3] |= (uint8_t)(1U << (idx & 7U));
}

static void clear_bit(uint8_t *map, size_t idx) {
    map[idx >> 3] &= (uint8_t)~(1U << (idx & 7U));
}

hxl1_rkp_result hxl1_rkp_model_init(hxl1_rkp_model *m,
                                    hxl1_rkp_range ram,
                                    hxl1_rkp_range externally_reserved,
                                    hxl1_rkp_range pool) {
    if (!m) {
        return HXL1_RKP_INVALID;
    }
    /* The caller must only initialize a zeroed or previously destroyed m. */
    memset(m, 0, sizeof(*m));
    if (!valid_range(ram) || !valid_range(externally_reserved) ||
        !valid_range(pool) || !inside(externally_reserved, ram) ||
        !inside(pool, externally_reserved)) {
        return HXL1_RKP_INVALID;
    }
    const uint64_t size = ram.end - ram.start;
    const uint64_t pool_size = pool.end - pool.start;
    if (size > (uint64_t)HXL1_RKP_MAX_UNITS * HXL1_RKP_SPARSE_UNIT_BYTES ||
        pool_size / HXL1_RKP_PAGE_BYTES > MAX_POOL_PAGES) {
        return HXL1_RKP_INVALID;
    }
    const size_t n = (size_t)(size / HXL1_RKP_SPARSE_UNIT_BYTES +
                       (size % HXL1_RKP_SPARSE_UNIT_BYTES != 0));
    const size_t pages = (size_t)(pool_size / HXL1_RKP_PAGE_BYTES);
    const size_t alloc_bytes = (pages + 7U) >> 3;
    uint8_t *allocation = calloc(alloc_bytes, 1);
    uint8_t *owner = calloc(n, (size_t)HXL1_RKP_BITMAP_BYTES_PER_UNIT);
    if (!allocation || !owner) {
        free(allocation);
        free(owner);
        return HXL1_RKP_OUT_OF_MEMORY;
    }
    m->guest_ram = ram;
    m->external_reservation = externally_reserved;
    m->protected_pool = pool;
    m->sparse_units = n;
    m->pool_pages = pages;
    m->allocated = allocation;
    m->owner_bitmap = owner;
    /* Fixed membership: a reserved physical page belongs to this pool
     * whether it is currently allocated or free. */
    for (uint64_t pa = pool.start; pa < pool.end; pa += HXL1_RKP_PAGE_BYTES) {
        const uint64_t ram_page = (pa - ram.start) / HXL1_RKP_PAGE_BYTES;
        set_bit(m->owner_bitmap, (size_t)ram_page);
    }
    return HXL1_RKP_OK;
}

void hxl1_rkp_model_destroy(hxl1_rkp_model *m) {
    if (!m) {
        return;
    }
    free(m->allocated);
    free(m->owner_bitmap);
    memset(m, 0, sizeof(*m));
}

bool hxl1_rkp_is_owned_pa(const hxl1_rkp_model *m, uint64_t pa) {
    if (!m || !m->owner_bitmap || pa < m->guest_ram.start ||
        pa >= m->guest_ram.end || (pa % HXL1_RKP_PAGE_BYTES) != 0) {
        return false;
    }
    const size_t idx = (size_t)((pa - m->guest_ram.start) /
                                HXL1_RKP_PAGE_BYTES);
    return test_bit(m->owner_bitmap, idx);
}

bool hxl1_rkp_is_allocated_pa(const hxl1_rkp_model *m, uint64_t pa) {
    if (!m || !m->allocated || !hxl1_rkp_is_owned_pa(m, pa)) {
        return false;
    }
    const size_t idx = (size_t)((pa - m->protected_pool.start) /
                                HXL1_RKP_PAGE_BYTES);
    return test_bit(m->allocated, idx);
}

hxl1_rkp_result hxl1_rkp_alloc_pa(hxl1_rkp_model *m, uint64_t *pa) {
    if (!m || !pa || !m->allocated || !m->owner_bitmap || !m->pool_pages) {
        return HXL1_RKP_INVALID;
    }
    *pa = 0;
    for (size_t n = 0; n < m->pool_pages; n++) {
        const size_t idx = (m->cursor + n) % m->pool_pages;
        if (test_bit(m->allocated, idx)) {
            continue;
        }
        set_bit(m->allocated, idx);
        m->cursor = (idx + 1) % m->pool_pages;
        *pa = m->protected_pool.start +
              (uint64_t)idx * HXL1_RKP_PAGE_BYTES;
        return HXL1_RKP_OK;
    }
    return HXL1_RKP_EXHAUSTED;
}

hxl1_rkp_result hxl1_rkp_free_pa(hxl1_rkp_model *m, uint64_t pa) {
    if (!m || !m->allocated || !hxl1_rkp_is_owned_pa(m, pa)) {
        return HXL1_RKP_INVALID;
    }
    const size_t idx = (size_t)((pa - m->protected_pool.start) /
                                HXL1_RKP_PAGE_BYTES);
    if (!test_bit(m->allocated, idx)) {
        return HXL1_RKP_NOT_ALLOCATED;
    }
    clear_bit(m->allocated, idx);
    m->cursor = idx; /* freed space should be reused before further growth */
    return HXL1_RKP_OK;
}

const uint8_t *hxl1_rkp_owner_unit(const hxl1_rkp_model *m, size_t unit) {
    if (!m || !m->owner_bitmap || unit >= m->sparse_units) {
        return NULL;
    }
    return m->owner_bitmap + unit * (size_t)HXL1_RKP_BITMAP_BYTES_PER_UNIT;
}

hxl1_rkp_descriptor_metadata hxl1_rkp_descriptor_fields(const hxl1_rkp_model *m) {
    hxl1_rkp_descriptor_metadata d = {0, 0, 0};
    if (m && m->owner_bitmap) {
        d.start_addr = m->guest_ram.start;
        d.end_addr = m->guest_ram.end;
        d.maxn = (uint64_t)m->sparse_units;
    }
    return d;
}
