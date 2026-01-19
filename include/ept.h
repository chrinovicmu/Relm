#ifndef EPT_H
#define EPT_H

#include <linux/types.h>
#include <vmx.h>
#include <vm.h> 

#define EPT_POINTER             0x0000201A

#define EPT_LEVLS               4
#define EPT_ENTRIES_PER_TABLE  512 

/*EPT page sizes */ 
#define EPT_PAGE_SIZE_4KB       (4ULL * 1024)
#define EPT_PAGE_SIZE_2MB       (2ULL * 1024 * 1024)
#define EPT_PAGE_SIZE_1GB       (1ULL * 1024 * 1024 * 1024)

/*EPT entry flags (bits in EPT PTE/PDE/PDPTE/PML4)*/ 

/*access rights bits(0-2) */ 

#define EPT_ACCESS_READ         (1ULL << 0)
#define EPT_ACCESS_WRITE        (1ULL << 1)
#define EPT_ACCESS_EXEC         (1ULL << 2)

/*memory type (bits 3-5) */ 
#define EPT_MEMTYPE_UC          (0ULL << 3)
#define EPT_MEMTYPE_WC          (1ULL << 4)
#define EPT_MEMTYPE_WT          (4ULL << 3)
#define EPT_MEMTYPE_WP          (5ULL << 3)
#define EPT_MEMTYPE_WB          (6ULL << 3)

/*ignore guest PAT memory type (bit 6)*/ 
#define EPT_IGNORE_PAT          (1ULL << 6)

#define EPT_PAGE_SIZE           (1ULL << 7)

#define EPT_ACCESSED            (1ULL << 8)
#define EPT_DIRTY               (1ULL << 9)

/*User-mode Execute (UME)
* when set, CPU will allow execution in ring 3 */ 
#define EPT_USER_EXEC           (1ULL << 10)

#define EPT_ADDR_MASK           0x000FFFFFFFFFF000ULL

#define EPT_RWX                 (EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC)
#define EPT_RW                  (EPT_ACCESS_READ | EPT_ACCESS_WRITE)
#define EPT_RX                  (EPT_ACCESS_READ | EPT_ACCESS_EXEC)
#define EPT_R                   (EPT_ACCESS_READ)

/*EPTP format */ 

/*EPTP is written to VMCS field EPT_POINTER (0x201A) 
* bits 2:0 -EPT paginf-structure memory type */ 
#define EPTP_MEMTYPE_UC         0ULL   
#define EPTP_MEMTYPE_WB         6ULL   
#define EPTP_MEMTYPE_MASK       0x7ULL 

/*bits 5:3 - EPT page-walk length minus 1) 
* 3 = 4 levels (PML4 -> PDPT -> PD -> PT) */ 
#define EPTP_PAGE_WALK_LENGTH_4 (3ULL << 3) 

/*enable access and dirty flags for EPT */ 
#define EPTP_ENABLE_AD_FLAGS    (1ULL << 6)

/*bits 11:7 - Reserved (must be 0)
* bits N:12 - Physical address of EPT PML4 table (4KB aligned) */ 

#define CONSTRUCT_EPTP(pml4_pa, memtype, enable_ad)  \ 
    (((pml4_pa) & EPT_ADDR_MASK) |                  \
     EPTP_PAGE_WALK_LENGTH_4 |                      \
     ((enable_ad) ? EPTP_ENABLE_AD_FLAGS : 0) |     \
     ((memtype) & EPTP_MEMTYPE_MASK))


/* EPT Table Entry structure */ 

typedef uint64_t ept_entry_t; 

/*EPT table structures - eahc is a page contaianing 512 entries */ 
typedef struct{
    ept_entry_t entries[EPT_ENTRIES_PER_TABLE]; 
} __attribute__((aligned(4096))) ept_pml4_t; 

typedef struct{
    ept_entry_t entries[EPT_ENTRIES_PER_TABLE]; 
} __attribute__((aligned(4096))) ept_pdpt_t; 

typedef struct{
    ept_entry_t entries[EPT_ENTRIES_PER_TABLE]; 
} __attribute__((aligned(4096))) ept_pd_t; 

typedef struct{
    ept_entry_t entries[EPT_ENTRIES_PER_TABLE]; 
} __attribute__((aligned(4096))) ept_pt_t; 

struct ept_context
{
    ept_pml4_t *pml4; 
    uint64_t pml4_pa; 

    /*EPTP value to write to VMCS */ 
    uint64_t eptp; 

    uint8_t memtype; 

    bool ad_enabled;

    /*stats */ 
    struct{
        uint64_t pages_4kb;  /*num of 4KB pages mapped */ 
        uint64_t pages_2mb;  /*num of 2MB pages mapped */ 
        uint64_t pages_1gb;  /*num of 1GB pages mapped */ 
        uint64_t total_mapped; 
    }stats; 

    spinlock_t lock; 

}; 

bool relm_ept_check_support(void); 
int relm_setup_ept(struct relm_vm *vm); 
struct ept_context *relm_ept_context_create(void); 
void relm_ept_context_destroy(struct ept_context *ept); 

/*map guest physical page to host physical page */ 
int relm_ept_map_page(struct ept_context *ept, uint64_t gpa,
                     uint64_t hpa, uint64_t flags); 

/*map a range of guest physical memory */ 
int relm_ept_map_range(struct ept_context *ept, uint64_t gpa_start,
                      uint64_t hpa_start, uint64_t size, uint64_t flags); 

int relm_ept_unmap_page(struct ept_context *ept, uint64_t gpa); 

/*look up host physicall address for gpa 
 * walk EPT tables to find HPA mapped to a given GPA*/ 
int relm_ept_get_mapping(struct ept_context *ept, uint64_t gpa, uint64_t *hpa); 

/*change memory type for a mapped page */ 
int relm_ept_set_memory_type(struct ept_context *ept, uint64_t gpa, uint8_t memtype); 

int relm_ept_handle_violation(struct vcpu *vcpu, uint64_t gpa, uint64_t exit_qualification); 

/*invalidate all TLB entries for EPT */ 
void relm_ept_invalidate_context(struct ept_context *ept); 

void relm_ept_dump_tables(struct ept_context *ept); 


/*extract indec for each level from a GPA */ 
#define EPT_PML4_INDEX(gpa)     (((gpa) >> 39) & 0x1FF)
#define EPT_PDPT_INDEX(gpa)     (((gpa) >> 30) & 0x1FF)
#define EPT_PD_INDEX(gpa)       (((gpa) >> 21) & 0x1FF)
#define EPT_PT_INDEX(gpa)       (((gpa) >> 12) & 0x1FF)
#define EPT_PAGE_OFFSET(gpa)    ((gpa) >> 0xFFF )


/*EPT capabality bits (IA32_VMX_EPT_VPID_CAP_ MSR) */ 

#define EPT_CAP_RWX_ONLY        (1ULL << 0)
#define EPT_CAP_PAGE_WALK_4     (1ULL << 6)
#define EPT_CAP_MEMTYPE_UC      (1ULL << 8)
#define EPT_CAP_MEMTYPE_WB      (1ULL << 14)
#define EPT_CAP_2MB_PAGES       (1ULL << 16)
#define EPT_CAP_1GB_PAGES       (1ULL << 17)
#define EPT_CAP_INVEPT          (1ULL << 20)
#define EPT_CAP_AD_FLAGS        (1ULL << 21)
#define EPT_CAP_INVEPT_SINGLE   (1ULL << 25) /*single context INVEPT */ 
#define EPT_CAP_INVEPT_ALL      (1ULL << 26) /*all-context INVEPT */ 

#endif /*EPT_H */ 
