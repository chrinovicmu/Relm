#include <asm-generic/errno.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <asm/io.h>
#include <asm/msr.h>

#include <include/vmx.h>
#include <include/vm.h>
#include <include/ept.h>
#include <include/vmx_ops.h>
#include <include/vmexit.h>
#include <include/vmcs_state.h>
#include <utils/utils.h>

static inline void _invept(uint64_t type, uint64_t eptp)
{
    struct{
        uint64_t eptp; 
        uint64_t reserved; 
    }__attribute__((packed)) descriptor = {
        .eptp = eptp, 
        .reserved = 0,  
    }; 

    __asm__ __volatile__ (
        "invept %0, %1\n"
        : 
        :"m" (descriptor), 
         "r" (type)
        :"memory", "cc"
    ); 
}

bool relm_ept_check_support(void)
{
    uint64_t ept_vpid_cap; 

    ept_vpid_cap = __rdmsr1(MSR_IA32_VMX_EPT_VPID_CAP); 

    if(!(ept_vpid_cap & EPT_CAP_PAGE_WALK_4))
    {
        pr_err("RELM: EPT 4-level page walk not supported\n"); 
        return false; 
    }

    if(!(ept_vpid_cap & EPT_CAP_MEMTYPE_WB))
    {
        pr_err("RELM: EPT write-back memory type not supported\n"); 
        return false; 
    }

    if(!(ept_vpid_cap & EPT_CAP_INVEPT))
    {
        pr_err("RELM: INVEPT instruction not supported\n"); 
        return false; 
    }

    pr_info("RELM: EPT support verified\n"); 

    if (ept_vpid_cap & EPT_CAP_2MB_PAGES)
        pr_info("RELM: EPT 2MB large pages supported\n");
    
    if (ept_vpid_cap & EPT_CAP_1GB_PAGES)
        pr_info("RELM: EPT 1GB large pages supported\n");
        
    if (ept_vpid_cap & EPT_CAP_AD_FLAGS)
        pr_info("RELM: EPT accessed/dirty flags supported\n");
    
    return true;
}

int relm_setup_ept(struct relm_vm *vm)
{
    if(!vm)
        return -EINVAL; 

    if(!relm_ept_check_support())
    {
        pr_err("RELM: EPT not supported on this CPU\n"); 
        return -ENOTSUPP; 
    }

    /*
    if(!relm_ept_enabled(vcpu))
    {
        pr_err("RELM: EPT not enabled in execution controls\n"); 
        return -EINVAL; 
    }
*/ 
    vm->ept = relm_ept_context_create(); 
    if(IS_ERR(vm->ept))
    {
        int err = PTR_ERR(vm->ept); 
        vm->ept = NULL; 
        pr_err("RELM: Failed to create EPT context: %d\n"); 
        return err; 
    }

    pr_info("RELM: EPT setup complete for VM %d (EPTP=0x%llx)\n", 
            vm->vm_id, vm->ept->eptp); 

    return 0; 
}

int relm_handle_ept_violation(struct relm_vm *vm)
{
    if(!vm || vm->ept)
        return -ENAVAIL; 

    uint64_t exit_qualification;
    uint64_t gpa; 
    bool data_read; 
    bool data_write; 
    bool instr_fetch;
    bool ept_present; 

    exit_qualification = __vmread(VM_EXIT_QUALIFICATION); 
    gpa = __vmread(GUEST_PHYSICAL_ADDRESS); 

    data_read = exit_qualification & (1ULL << 0);
    data_write = exit_qualification & (1ULL << 1);
    instr_fetch = exit_qualification & (1ULL << 2);
    ept_present = exit_qualification & (1ULL << 3);
    
    pr_err("RELM: EPT violation at GPA 0x%llx\n", gpa);
    pr_err("  Access type: %s%s%s\n",
           data_read ? "Read " : "",
           data_write ? "Write " : "",
           instr_fetch ? "Exec " : "");
    pr_err("  EPT entry: %s\n",
           ept_present ? "Present (permission violation)" : "Not present");
    pr_err("  Guest RIP: 0x%llx\n", __vmread(GUEST_RIP));
   
    /*treat EPT violations as fatat for now */ 
    return -EFAULT; 
}

int relm_vcpu_handle_ept_misconfig(struct relm_vm *vm)
{
    uint64_t gpa; 
    gpa = __vmread(GUEST_PHYSICAL_ADDRESS); 

    pr_err("RELM: EPT misconfiguration at GPA 0x%llx\n", gpa);
    pr_err("  Guest RIP: 0x%llx\n", __vmread(GUEST_RIP));
    pr_err("  This indicates a bug in EPT setup code!\n");
    
    if(vm->ept)
        relm_ept_dump_tables(vm->ept); 

    return -EFAULT; 

}


struct ept_context *relm_ept_context_create(void)
{
    struct ept_context *ept; 

    ept = kzalloc(sizeof(*ept), GFP_KERNEL); 
    if(!ept)
    {
        pr_err("RELM: Failed to allocate EPT context\n"); 
        return ERR_PTR(-ENOMEM); 
    }

    /*allocate root PML4 , 4kb page-aligned, zeroed*/ 
    ept->pml4 = (ept_pml4_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO); 
    if(!ept->pml4)
    {
        pr_err("RELM: Failed to allocate EPT PML4 table\n"); 
        kfree(ept); 
        return ERR_PTR(-ENOMEM); 
    }
    ept->pml4_pa = virt_to_phys(ept->pml4); 

    ept->memtype = EPTP_MEMTYPE_WB;

    /*A/D flags disabled for now */ 
    ept->ad_enabled = false; 

    ept->eptp = CONSTRUCT_EPTP(ept->pml4_pa, ept->memtype, ept->ad_enabled); 

    memset(&ept->stats, 0, sizeof(ept->stats)); 

    spin_lock_init(&ept->lock); 

    pr_info("RELM : EPT context created, PML4 PA=0x%llx, EPTP=0x%llx\n", 
            ept->pml4_pa, ept->eptp); 

    return ept; 
}

static void relm_ept_free_table(void *table_va, int level)
{
    ept_entry_t *entries = (ept_entry_t *)table_va; 
    int i; 

    if(level == 1)
    {
        free_page((unsigned long)table_va); 
        return; 
    }

    for(i = 0; i < EPT_ENTRIES_PER_TABLE; i++)
    {
        ept_entry_t entry = entries[i]; 

        /*skip empty entries */ 
        if(!(entry & EPT_ACCESS_READ))
            continue; 

        /*check if this is a large page */ 
        if(entry & EPT_PAGE_SIZE)
            continue; 

        uint64_t child_pa = entry & EPT_ADDR_MASK; 

        void *child_va = phys_to_virt(child_pa); 

        relm_ept_free_table(child_va, level - 1); 
    }

    free_page((unsigned)table_va);
}

void relm_ept_context_destroy(struct ept_context *ept)
{
    if(!ept)
        return; 

    if(ept->pml4)
    {
        relm_ept_free_table(ept->pml4, 4); 
        ept->pml4 = NULL; 
        ept->pml4_pa = 0; 
    }

    pr_info("RELM: EPT context destroyed (mapped %llu bytes)\n", 
            ept->stats.total_mapped); 

    kfree(ept); 
}

static inline void *relm_ept_alloc_table(void)
{
    void *table = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO); 
    if(_unlikely(!table))
    {
        pr_err("RELM: Failed to alloc EPT table\n");
        return NULL; 
    }

    return table; 
}

static void *relm_ept_get_or_create_table(ept_entry_t *entry_ptr, int level)
{
    ept_entry_t entry = *entry_ptr; 
    void *table_va; 
    uint64_t table_pa; 

    if(entry & EPT_ACCESS_READ)
    {
        return phys_to_virt(entry & EPT_ADDR_MASK);  
    }

    table_va = relm_ept_alloc_table(); 
    if(!table_va)
        return NULL; 

    table_pa = virt_to_phys(table_va); 

    /*create entry pointing to new table 
     * for non-leaf entries , we give RWX permissions*/ 
    *entry_ptr = (table_pa & EPT_ADDR_MASK) | EPT_RWX; 

    return table_va; 
}

int relm_ept_map_page(struct ept_context *ept, uint64_t gpa, 
                     uint64_t hpa, uint64_t flags) 
{
    ept_pdpt_t *pdpt; 
    ept_pd_t *pd; 
    ept_pt_t *pt; 

    unsigned long irq_flags ; 

    if(!ept || !ept->pml4)
    {
        pr_err("RELM: Invalid EPT context\n"); 
        return -EINVAL; 
    }

    /*ensure addresses are page-aligned */ 
    if((gpa & 0xFFF) || (hpa & 0xFFF))
    {
        pr_err("RELM: Addresses must be 4KB aligned (GPA=0x%llx, HPA=0x%llx)\n",
               gpa, hpa); 
        return -EINVAL; 
    }

    /*ensure at least read permission is set */ 
    if(!(flags & EPT_ACCESS_READ))
    {
        pr_err("RELM: EPT mapping must have at least read access\n");
        return -EINVAL; 
    }

    spin_lock_irqsave(&ept->lock, irq_flags); 

    uint32_t pml4_index = EPT_PML4_INDEX(gpa); 

    /*get PDPT table*/ 
    pdpt = (ept_pdpt_t *)relm_ept_get_or_create_table(
        &ept->pml4->entries[pml4_index], 3);
    if(!pdpt)
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOMEM; 
    }

    uint32_t pdpt_idx = EPT_PDPT_INDEX(gpa); 

    pd = (ept_pd_t *)relm_ept_get_or_create_table(
        &pdpt->entries[pdpt_idx], 2);
    if(!pd)
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOMEM; 
    }

    uint32_t pd_idx = EPT_PD_INDEX(gpa); 

    pt = (ept_pt_t *)relm_ept_get_or_create_table(
        &pd->entries[pd_idx], 1); 
    if(!pt)
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOMEM; 
    }

    uint32_t pt_idx = EPT_PT_INDEX(gpa); 

    ept_entry_t *leaf_entry = &pt->entries[pt_idx]; 

    if(*leaf_entry & EPT_ACCESS_READ)
    {
        pr_warn("RELM: GPA 0x%llx already mapped, overwriting\n", gpa); 
    }
    else{
        ept->stats.pages_4kb++; 
        ept->stats.total_mapped += EPT_PAGE_SIZE_4KB; 
    }
    
    *leaf_entry = (hpa & EPT_ADDR_MASK) | flags | EPT_MEMTYPE_WB;

    spin_unlock_irqrestore(&ept->lock, irq_flags); 

    PDEBUG("RELM: Mapped GPA 0x%llx -> HPA 0x%llx (flags=0x%llx)\n",
           gpa, hpa, flags);
    
    relm_ept_invalidate_context(ept); 
    return 0; 
}

/*map multiple pages in a loop */ 
int relm_ept_map_range(struct ept_context *ept, uint64_t gpa_start, 
                      uint64_t hpa_start, uint64_t size, uint64_t flags)
{
    uint64_t gpa; 
    uint64_t hpa; 
    uint64_t num_pages; 
    uint64_t i; 
    int ret; 

    if(!ept)
        return -EINVAL; 

    /*round size to 4KB page boundary */ 
    size = PAGE_ALIGN(size); 
    num_pages = size / EPT_PAGE_SIZE_4KB; 

    pr_info("RELM: Mapping EPT range GPA 0x%llx -> HPA 0x%llx (%llu pages)\n",
            gpa_start, hpa_start, num_pages); 

    /*map each page in the range */ 
    for(i = 0; i < num_pages; i++)
    {
        gpa = gpa_start + (i * EPT_PAGE_SIZE_4KB); 
        hpa = hpa_start + (i * EPT_PAGE_SIZE_4KB); 

        ret = relm_ept_map_page(ept, gpa, hpa, flags);
        if(ret < 0)
        {
            pr_err("RELM: Failed to map page %llu/%llu (GPA=0x%llx)\n", 
                   i + 1, num_pages, gpa); 
            return ret; 
        }
    }

    pr_info("RELM: Successfully mapped %llu pages\n", num_pages);

    return 0;
}

/*walks EPT table to find the leaf entry and clear it */ 
int relm_unmap_page(struct ept_context *ept, uint64_t gpa)
{
    ept_pdpt_t *pdpt; 
    ept_pd_t *pd; 
    ept_pt_t *pt; 
    ept_entry_t *leaf_entry; 
    unsigned long irq_flags; 
    uint32_t pml4_idx; 
    uint32_t pdpt_idx;
    uint32_t pd_idx;
    uint32_t pt_idx;

    if (!ept || !ept->pml4)
        return -EINVAL; 

    spin_lock_irqsave(&ept->lock, irq_flags); 

    pml4_idx = EPT_PML4_INDEX(gpa); 

    if(!(ept->pml4->entries[pml4_idx] & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    pdpt = (ept_pdpt_t *)phys_to_virt(
        ept->pml4->entries[pml4_idx] & EPT_ADDR_MASK);

    pdpt_idx = EPT_PDPT_INDEX(gpa); 

    if(!(pdpt->entries[pdpt_idx] & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    pd = (ept_pd_t*)phys_to_virt(
        pdpt->entries[pdpt_idx] & EPT_ADDR_MASK); 

    pd_idx = EPT_PD_INDEX(gpa); 

    if(!(pd->entries[pd_idx] & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    pt = (ept_pt_t*)phys_to_virt(
        pd->entries[pd_idx] & EPT_ADDR_MASK); 

    pt_idx = EPT_PT_INDEX(gpa); 

    leaf_entry = &pt->entries[pt_idx]; 

    if(!(*leaf_entry & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    /*clear leaf entry */ 
    *leaf_entry = 0; 

    ept->stats.pages_4kb--; 
    ept->stats.total_mapped -= EPT_PAGE_SIZE_4KB; 

    spin_unlock_irqrestore(&ept->lock, irq_flags);

    /*invalidate EPT TLB entries for the entir context to ensure consistency */ 
    relm_ept_invalidate_context(ept); 

    PDEBUG("RELM: Unmapped GPA 0x%llx\n", gpa);

    return 0; 
}

/*walk EPT tables to find the HPA of given GPA */  
int relm_get_mapping(struct ept_context *ept, uint64_t gpa, uint64_t *hpa)
{
    ept_pdpt_t *pdpt; 
    ept_pd_t *pd; 
    ept_pt_t *pt; 
    ept_entry_t leaf_entry; 
    unsigned long irq_flags; 

    uint32_t pml4_idx; 
    uint32_t pdpt_idx;
    uint32_t pd_idx;
    uint32_t pt_idx;

    if(!ept || !ept->pml4)
        return -EINVAL; 

    spin_lock_irqsave(&ept->lock, irq_flags); 

    pml4_idx = EPT_PML4_INDEX(gpa); 

    if(!(ept->pml4->entries[pml4_idx] & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    pdpt = (ept_pdpt_t*)phys_to_virt(
        ept->pml4->entries[pml4_idx] & EPT_ADDR_MASK); 

    pdpt_idx = EPT_PDPT_INDEX(gpa); 

    if(!(pdpt->entries[pdpt_idx] & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    pd = (ept_pd_t *)phys_to_virt(
        pdpt->entries[pdpt_idx] & EPT_ADDR_MASK);

    pd_idx = EPT_PD_INDEX(gpa); 

    if(!(pd->entries[pd_idx] & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    pt = (ept_pt_t *)phys_to_virt(
        pd->entries[pd_idx] & EPT_ADDR_MASK); 

    pt_idx = EPT_PT_INDEX(gpa); 

    leaf_entry = pt->entries[pt_idx]; 

    if(!(leaf_entry & EPT_ACCESS_READ))
    {
        spin_unlock_irqrestore(&ept->lock, irq_flags); 
        return -ENOENT; 
    }

    /*extract host physical address*/ 
    *hpa = (leaf_entry & EPT_ADDR_MASK) |
        EPT_PAGE_OFFSET(gpa); 

    spin_unlock_irqrestore(&ept->lock, irq_flags); 

    return 0; 
}

/*flush all cached ept translations */ 
void relm_ept_invalidate_context(struct ept_context *ept)
{
    if(!ept)
        return; 

    _invept(1, ept->eptp);

    PDEBUG("RELM: Invalidated EPT context (EPTP=0x%llx)\n", ept->eptp);
}

void relm_ept_dump_tables(struct ept_context *ept)
{
    int pml4_idx;
    int pdpt_idx;
    int pd_idx; 
    int pt_idx;
    ept_pdpt_t *pdpt;
    ept_pd_t *pd;
    ept_pt_t *pt;
    
    if (!ept || !ept->pml4)
        return;
    
    pr_info("=== EPT Table Dump ===\n");
    pr_info("EPTP: 0x%llx\n", ept->eptp);
    pr_info("PML4 PA: 0x%llx\n", ept->pml4_pa);
    pr_info("Stats: %llu x 4KB, %llu x 2MB, %llu x 1GB pages\n",
            ept->stats.pages_4kb, ept->stats.pages_2mb, ept->stats.pages_1gb);
    pr_info("Total mapped: %llu bytes\n", ept->stats.total_mapped);
    
    for (pml4_idx = 0; pml4_idx < EPT_ENTRIES_PER_TABLE; pml4_idx++) 
    {
        if (!(ept->pml4->entries[pml4_idx] & EPT_ACCESS_READ))
            continue;
        
        pdpt = (ept_pdpt_t *)phys_to_virt(
            ept->pml4->entries[pml4_idx] & EPT_ADDR_MASK);
        
        for (pdpt_idx = 0; pdpt_idx < EPT_ENTRIES_PER_TABLE; pdpt_idx++) 
        {
            if (!(pdpt->entries[pdpt_idx] & EPT_ACCESS_READ))
                continue;
            
            pd = (ept_pd_t *)phys_to_virt(
                pdpt->entries[pdpt_idx] & EPT_ADDR_MASK);
            
            for (pd_idx = 0; pd_idx < EPT_ENTRIES_PER_TABLE; pd_idx++)
            {
                if (!(pd->entries[pd_idx] & EPT_ACCESS_READ))
                    continue;
                
                pt = (ept_pt_t *)phys_to_virt(
                    pd->entries[pd_idx] & EPT_ADDR_MASK);
                
                for (pt_idx = 0; pt_idx < EPT_ENTRIES_PER_TABLE; pt_idx++) 
                {
                    ept_entry_t entry = pt->entries[pt_idx];
                    
                    if (!(entry & EPT_ACCESS_READ))
                        continue;
                    
                    uint64_t gpa = ((uint64_t)pml4_idx << 39) |
                                   ((uint64_t)pdpt_idx << 30) |
                                   ((uint64_t)pd_idx << 21) |
                                   ((uint64_t)pt_idx << 12);
                    uint64_t hpa = entry & EPT_ADDR_MASK;
                    char perms[4] = {
                        (entry & EPT_ACCESS_READ) ? 'R' : '-',
                        (entry & EPT_ACCESS_WRITE) ? 'W' : '-',
                        (entry & EPT_ACCESS_EXEC) ? 'X' : '-',
                        '\0'
                    };
                    
                    pr_info("  GPA 0x%llx -> HPA 0x%llx [%s]\n",
                            gpa, hpa, perms);
                }
            }
        }
    }
    
    pr_info("=== End EPT Dump ===\n");
}
