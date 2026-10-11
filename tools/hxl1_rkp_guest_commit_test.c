/* SPDX-License-Identifier: MIT
 * Fictional guest-address backend for testing write ordering / rollback.
 * No QEMU or handset. 2GiB guest RAM is NOT allocated by this fixture.
 */
#include "hxl1_rkp_guest_commit.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    hxl1_rkp_guest_plan plan;
    uint8_t slot[8];
    uint8_t descriptor[32];
    uint8_t table[16];
    uint8_t bitmap[65536];
    size_t verifications, writes, reads;
    int fail_write_at, fail_verify_at, fail_read_at;
    bool fail_restore, corrupt_readback;
    bool write_order_error;
    bool fault_was_injected;
} fixture;

static hxl1_rkp_guest_plan make_plan(void) {
    hxl1_rkp_guest_plan p={
        .global_slot={0xffffff800a4dd0b8ULL,0x40002000ULL,8},
        .descriptor={0xffffff800b000000ULL,0x60000000ULL,32},
        .pointer_table={0xffffff800b001000ULL,0x60001000ULL,16},
        .bitmap_data={0xffffff800b002000ULL,0x60002000ULL,65536},
    };
    return p;
}

static hxl1_rkp_model make_model(void) {
    hxl1_rkp_model m={0};
    const hxl1_rkp_range ram={0x40000000ULL,0xc0000000ULL};
    const hxl1_rkp_range reserve={0x60000000ULL,0x60030000ULL};
    const hxl1_rkp_range pool={0x60020000ULL,0x60024000ULL};
    assert(hxl1_rkp_model_init(&m,ram,reserve,pool)==HXL1_RKP_OK);
    return m;
}

static bool mapped(void *opaque,uint64_t va,uint64_t pa,uint64_t n,bool writable) {
    fixture *f=opaque;
    const hxl1_rkp_guest_mapping *maps[]={
        &f->plan.global_slot,&f->plan.descriptor,
        &f->plan.pointer_table,&f->plan.bitmap_data
    };
    f->verifications++;
    if (f->fail_verify_at && (int)f->verifications == f->fail_verify_at) return false;
    if (!writable) return false;
    for (size_t i=0;i<4;i++) {
        if (maps[i]->va==va && maps[i]->pa==pa && maps[i]->size==n) return true;
    }
    return false;
}
static uint8_t *area(fixture *f,uint64_t pa,size_t len) {
    const struct {
        uint64_t pa;
        size_t len;
        uint8_t *bytes;
    } pieces[]={
        {f->plan.global_slot.pa,sizeof(f->slot),f->slot},
        {f->plan.descriptor.pa,sizeof(f->descriptor),f->descriptor},
        {f->plan.pointer_table.pa,sizeof(f->table),f->table},
        {f->plan.bitmap_data.pa,sizeof(f->bitmap),f->bitmap},
    };
    for (size_t i=0;i<4;i++) {
        if (pa==pieces[i].pa && len==pieces[i].len) return pieces[i].bytes;
    }
    return NULL;
}
static bool memory_read(void *opaque,uint64_t pa,uint8_t *dst,size_t len) {
    fixture *f=opaque;
    f->reads++;
    if (f->fail_read_at && (int)f->reads==f->fail_read_at) return false;
    uint8_t *p=area(f,pa,len);
    if (!p) return false;
    memcpy(dst,p,len);
    if (f->corrupt_readback && !f->fault_was_injected && f->reads>4) {
        dst[0]^=0x80;
        f->fault_was_injected=true;
    }
    return true;
}
static bool allzero(const uint8_t *p,size_t len) {
    for(size_t i=0;i<len;i++)if(p[i]!=0)return false;
    return true;
}
static bool memory_write(void *opaque,uint64_t pa,const uint8_t *src,size_t len) {
    fixture *f=opaque;
    uint8_t *p=area(f,pa,len);
    if (!p) return false;
    f->writes++;
    /* All forward writes have nonzero buffers in these fixture cases.
     * A zero-buffer write is a rollback of original bytes.
     */
    if (allzero(src,len) && f->fail_restore) return false;
    if (!allzero(src,len)) {
        const uint64_t expected[]={
            f->plan.bitmap_data.pa,
            f->plan.pointer_table.pa,
            f->plan.descriptor.pa,
            f->plan.global_slot.pa
        };
        if (f->writes<=4 && pa != expected[f->writes-1]) {
            f->write_order_error=true;
        }
        if (pa != f->plan.global_slot.pa && !allzero(f->slot,sizeof(f->slot))) {
            f->write_order_error=true;
        }
    }
    if (f->fail_write_at && (int)f->writes==f->fail_write_at) {
        /* Simulate partial success before reporting failure. */
        memcpy(p,src,len==8 ? len-1 : len/2);
        return false;
    }
    memcpy(p,src,len);
    return true;
}
static hxl1_rkp_guest_backend backend(void) {
    hxl1_rkp_guest_backend b={
        .verify_va_pa=mapped,
        .read_pa=memory_read,
        .write_pa=memory_write,
        .all_vcpus_quiesced=true,
        .ram_reservation_verified=true,
    };
    return b;
}
static void empty_all(fixture *f) {
    assert(allzero(f->slot,sizeof(f->slot)));
    assert(allzero(f->descriptor,sizeof(f->descriptor)));
    assert(allzero(f->table,sizeof(f->table)));
    assert(allzero(f->bitmap,sizeof(f->bitmap)));
}
static uint64_t load64(const uint8_t *p) {
    uint64_t v=0;
    for(int i=7;i>=0;i--) v=(v<<8)|p[i];
    return v;
}

static void test_success(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==HXL1_RKP_COMMIT_OK);
    assert(!f.write_order_error && f.writes==4 && tr.writes_verified==4);
    assert(tr.pointer_published && tr.snapshots_read==4);
    assert(tr.mappings_verified==12);
    assert(load64(f.slot)==f.plan.descriptor.va);
    assert(load64(f.descriptor+24)==f.plan.pointer_table.va);
    assert(load64(f.table)==f.plan.bitmap_data.va);
    assert(load64(f.table+8)==f.plan.bitmap_data.va+32768);
    assert(f.bitmap[(0x60020000ULL-0x40000000ULL)/4096/8]!=0);
    hxl1_rkp_model_destroy(&m);
}

static void test_failed_partial_write_rolls_back(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    f.fail_write_at=3; /* descriptor partially written */
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_WRITE_FAILED_ROLLED_BACK);
    assert(tr.rollbacks_attempted==3 && tr.rollbacks_verified==3);
    assert(tr.rollback_complete && !tr.pointer_published);
    empty_all(&f);
    hxl1_rkp_model_destroy(&m);
}
static void test_rollback_failure_reports_untrusted_ram(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    f.fail_write_at=2;
    f.fail_restore=true;
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_ROLLBACK_FAILED);
    assert(!tr.rollback_complete && tr.rollbacks_attempted==2);
    assert(!tr.pointer_published);
    assert(!allzero(f.bitmap,sizeof(f.bitmap)));
    hxl1_rkp_model_destroy(&m);
}
static void test_uncertain_kernel_global_after_failed_rollback(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    f.fail_write_at=4; /* original kernel pointer, partially written */
    f.fail_restore=true; /* physical backend cannot restore guest bytes */
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_ROLLBACK_FAILED);
    assert(!tr.rollback_complete);
    assert(tr.publication_state_uncertain);
    assert(!allzero(f.slot,sizeof(f.slot)));
    hxl1_rkp_model_destroy(&m);
}
static void test_preexisting_memory_is_never_overwritten(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    f.slot[0]=1;
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_ALREADY_INITIALIZED);
    assert(!f.writes && f.slot[0]==1);
    f.slot[0]=0;
    f.bitmap[8]=2;
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_DIRTY_RESERVED_MEMORY);
    assert(!f.writes && f.bitmap[8]==2);
    hxl1_rkp_model_destroy(&m);
}
static void test_mid_transaction_mapping_failure_rolls_back(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    f.fail_verify_at=12; /* final publish: 4 stage + 4 snapshot + 4 write */
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_MAPPING_UNVERIFIED);
    assert(tr.writes_verified==3 && tr.rollbacks_verified==3);
    assert(!tr.pointer_published && tr.rollback_complete);
    empty_all(&f);
    hxl1_rkp_model_destroy(&m);
}
static void test_readback_failure_rolls_back(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    f.corrupt_readback=true;
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_WRITE_FAILED_ROLLED_BACK);
    assert(f.fault_was_injected && tr.rollbacks_verified==1);
    empty_all(&f);
    hxl1_rkp_model_destroy(&m);
}
static void test_paused_and_reserved_are_required(void) {
    hxl1_rkp_model m=make_model();
    fixture f={0};
    f.plan=make_plan();
    hxl1_rkp_guest_backend b=backend();
    hxl1_rkp_commit_trace tr={0};
    b.ram_reservation_verified=false;
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_PRECONDITION);
    b.ram_reservation_verified=true;
    b.all_vcpus_quiesced=false;
    assert(hxl1_rkp_guest_commit(&m,&f.plan,&b,&f,&tr)==
           HXL1_RKP_COMMIT_PRECONDITION);
    assert(f.verifications==0 && f.writes==0 && f.reads==0);
    hxl1_rkp_model_destroy(&m);
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    if(strcmp(argv[1],"success")==0)test_success();
    else if(strcmp(argv[1],"partial")==0)test_failed_partial_write_rolls_back();
    else if(strcmp(argv[1],"rollback-fail")==0)test_rollback_failure_reports_untrusted_ram();
    else if(strcmp(argv[1],"publish-uncertain")==0)test_uncertain_kernel_global_after_failed_rollback();
    else if(strcmp(argv[1],"dirty")==0)test_preexisting_memory_is_never_overwritten();
    else if(strcmp(argv[1],"mapping")==0)test_mid_transaction_mapping_failure_rolls_back();
    else if(strcmp(argv[1],"readback")==0)test_readback_failure_rolls_back();
    else if(strcmp(argv[1],"preconditions")==0)test_paused_and_reserved_are_required();
    else return 3;
    printf("[PASS] host-only transactional RKP %s\n",argv[1]);
    return 0;
}
