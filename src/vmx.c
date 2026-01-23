#include <asm/processor-flags.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/smp.h> 
#include <linux/kthread.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/desc.h> 

#include <include/vmx.h>
#include <include/vm.h>
#include <include/ept.h>
#include <include/vmx_ops.h>
#include <include/vmexit.h>
#include <include/vmcs_state.h>
#include <utils/utils.h>

static int relm_setup_vmxon_region(struct host_cpu *hcpu);
static int relm_setup_vmcs_region(struct vcpu *vcpu);
static int relm_setup_io_bitmap(struct vcpu *vcpu);
static int relm_setup_msr_bitmap(struct vcpu *vcpu);
static int relm_setup_msr_areas(struct vcpu *vcpu,
                               const uint32_t *vmexit_list,  size_t vmexit_count,
                               const uint32_t *vmentry_list, const uint64_t *vmentry_values,
                               size_t vmentry_count);

static int relm_vcpu_setup_msr_state(struct vcpu *vcpu);
static int relm_setup_exec_controls(struct vcpu *vcpu);
static int vmx_apply_exec_controls(struct vcpu *vcpu);
static void vmx_init_exec_controls(struct vcpu *vcpu);

static void relm_free_io_bitmap(struct vcpu *vcpu);
static void relm_free_msr_bitmap(struct vcpu *vcpu);
static void relm_free_vmcs_region(struct vcpu *vcpu);
static void relm_free_all_msr_areas(struct vcpu *vcpu);
static void relm_free_vmxon_region(struct host_cpu *hcpu);

static struct msr_entry *alloc_msr_entry(size_t n_entries);
static void free_msr_area(struct msr_entry *area, size_t n_entries);
static void populate_msr_load_area(struct msr_entry *area, size_t count,
                                   const uint32_t *indices, const uint64_t *values);
static void populate_msr_store_area(struct msr_entry *area, size_t count, 
                                    const uint32_t *indices);

static inline bool relm_vcpu_io_bitmap_enabled(struct vcpu *vcpu);
static inline bool relm_vcpu_msr_bitmap_enabled(struct vcpu *vcpu);
static inline unsigned int msr_area_order(size_t bytes);


const uint32_t relm_vmexit_msr_indices[] = {
    MSR_IA32_EFER,
    MSR_IA32_STAR,
    MSR_IA32_LSTAR,
    MSR_IA32_CSTAR,
    MSR_IA32_FMASK,
    MSR_IA32_FS_BASE,
    MSR_IA32_GS_BASE
};

#define RELM_VMEXIT_MSR_COUNT \ 
    ARRAY_SIZE(relm_vmexit_msr_indices)

const uint32_t relm_vmentry_msr_indices[] = {
    MSR_IA32_EFER,
    MSR_IA32_STAR,
    MSR_IA32_LSTAR,
    MSR_IA32_CSTAR,
    MSR_IA32_FMASK,
    MSR_IA32_FS_BASE,
    MSR_IA32_GS_BASE
};

#define RELM_VMENTRY_MSR_COUNT \
    ARRAY_SIZE(relm_vmentry_msr_indices)

uint64_t relm_vmentry_msr_values[RELM_VMENTRY_MSR_COUNT]; 


inline bool relm_vmx_support(void) 
{
    unsigned int eax = 1, ebx, ecx = 0, edx;

    __asm__ volatile (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
        : "memory"
    );  

    pr_info("RELM: CPUID(1) ECX=0x%x\n", ecx);

    return (ecx & (1 << 5)) != 0;  /* VMX bit */
}

inline void relm_enable_vmx_operation(void)
{
    uint64_t cr4;

    /* Read CR4 safely */
    asm volatile("mov %%cr4, %0" : "=r"(cr4));

    /* Only set VMXE if not already set */
    if (!(cr4 & (1UL << 13))) {
        cr4 |= (1UL << 13);
        asm volatile("mov %0, %%cr4" :: "r"(cr4) : "memory");
    }

    /* Optional verification (for debug) */
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    if (!(cr4 & (1UL << 13)))
        pr_err("RELM: VMXE bit not set in CR4!\n");

    pr_info("RELM: VMX operation enabled\n"); 
}

bool relm_setup_feature_control(void)
{
    uint64_t fc; 

    fc = __rdmsr1(MSR_IA32_FEATURE_CONTROL); 

    const uint64_t required = 
        IA32_FEATURE_CONTROL_LOCKED | 
        IA32_FEATURE_CONTROL_MSR_VMXON_ENABLE_OUTSIDE_SMX;

    /* If MSR is locked, verify VMXON is allowed */ 
    if (fc & IA32_FEATURE_CONTROL_LOCKED) {
        if (!(fc & IA32_FEATURE_CONTROL_MSR_VMXON_ENABLE_OUTSIDE_SMX)) {
            pr_err("RELM: Feature control locked but VMXON not enabled\n"); 
            return false; 
        }
        return true; 
    }

    /* Lock MSR and set required bits */
    __wrmsr(MSR_IA32_FEATURE_CONTROL,
             (uint32_t)(fc | required & 0xFFFFFFFF),
             (uint32_t)((fc | required >> 32) & 0xFFFFFFFF)); 

    fc = __rdmsr1(MSR_IA32_FEATURE_CONTROL); 
    if ((fc & required) != required) {
        pr_err("RELM: Failed to lock/setup IA32_FEATURE_CONTROL MSR\n"); 
        return false; 
    }

    return true;
}

/*pin vcpu thread to a specific physical host cpu for cpu affinity*/ 
int relm_vcpu_pin_to_cpu(struct vcpu *vcpu, int target_cpu_id)
{
    int ret; 

    if(!vcpu->host_task)
    {
        pr_err("RELM: VCPU %d has no host task assigned.\n", vcpu->vpid); 
        return -EINVAL; 
    }

    cpumask_t new_mask; 

    if(!cpu_possible(target_cpu_id))
    {
        pr_err("RELM: Invalid host CPU ID %d for pinning VCPU %d.\n", 
               target_cpu_id, vcpu->vpid); 
        return -EINVAL; 
    }

    cpumask_clear(&new_mask); 
    cpumask_set_cpu(target_cpu_id, &new_mask); 

    ret = set_cpus_allowed_ptr(vcpu->host_task, &new_mask); 
    if(ret == 0)
    {
        PDEBUG("RELM: Successfuly pinned VCPU %d to Host CPU %d.\n", 
               vcpu->vpid, target_cpu_id); 
    }
    else{
        pr_err("RELM: Failed to pin VCPU %d to CPU %d, error : %d\n", 
               vcpu->vpid, target_cpu_id, ret); 
    }

    return ret; 
}

/*IO bitmap bit in the execution controls need to be set in order to use io bimaps*/ 
static inline bool relm_vcpu_io_bitmap_enabled(struct vcpu *vcpu)
{
    return vcpu->controls.primary_proc & VMCS_PROC_USE_IO_BITMAPS; 
}

/*MSR bitmap bit in the execution controls need to be set in order to use msr bimaps */ 
static inline bool relm_vcpu_msr_bitmap_enabled(struct vcpu *vcpu)
{
    return vcpu->controls.primary_proc & VMCS_PROC_USE_MSR_BITMAPS; 
}

static inline bool relm_vcpu_ept_enabled(struct vcpu *vcpu)
{
    return (vcpu->controls.secondary_proc & VMCS_PROC2_ENABLE_EPT) != 0;
}

void relm_vcpu_unpin_and_stop(struct vcpu *vcpu)
{
    set_cpus_allowed_ptr(vcpu->host_task, cpu_online_mask); 
    kthread_stop(vcpu->host_task); 
}

static int relm_setup_vmxon_region(struct host_cpu *hcpu)
{
    if(!hcpu)
        return -EINVAL; 

    /*allocate one page, page-aligned, zeroed */ 
    hcpu->vmxon = (struct vmxon_region *)__get_free_page(GFP_KERNEL | __GFP_ZERO); 
    if(!hcpu->vmxon)
        return -ENOMEM; 

    /*set VMX revision identifier */ 
    *(uint32_t *)hcpu->vmxon = _vmcs_revision_id(); 
    hcpu->vmxon_pa = virt_to_phys(hcpu->vmxon); 

    PDEBUG("VMXON region physicall address : 0x%llx\n", hcpu->vmxon_pa);     
    return 0; 
}

static int relm_vmxon(struct host_cpu *hcpu)
{
    uint64_t rflags; 

    if(!hcpu || !hcpu->vmxon_pa)
    {
        pr_err("RELM: Invalid vmxon region\n"); 
        return -EINVAL; 
    }

    asm volatile (
        "vmxon %[pa]\n\t"           
        "pushfq\n\t"                
        "popq %[rflags]\n\t"        
        : [rflags] "=r" (rflags)    
        : [pa] "m" (hcpu->vmxon_pa) 
        : "cc", "memory"            
    );

    if(rflags & X86_EFLAGS_CF)
    {
        pr_err("RELM: VMXON failed - VMfailInvalid (CF=1)\n"); 
        pr_err("RELM: VMXON INSTRUCTION ERROR: %d\n", __vmread(VMCS_INSTRUCTION_ERROR_FIELD)); 
        return -EIO; 
    }
    if(rflags & X86_EFLAGS_ZF)
    {   
        pr_err("RELM: VMXON failed - VMfailValid (ZF=1)\n"); 
        pr_err("RELM: VMXON INSTRUCTION ERROR: %d\n", __vmread(VMCS_INSTRUCTION_ERROR_FIELD)); 
        return -EIO; 
    }
    
    pr_info("RELM: VMXON successful, CPU in VMX root operation\n"); 
    return 0; 
}

static int relm_vmxoff(struct host_cpu *hcpu)
{
    uint64_t rflags; 

    asm volatile (
        "vmxoff\n\t"
        "pushfq\n\t"
        "popq %[rflags]\n\t"
        : [rflags] "=r" (rflags)
        :
        : "cc", "memory"
    );

     if (rflags & X86_EFLAGS_CF)
    {
        pr_err("RELM: VMXOFF failed - VMfailInvalid\n");
        return -EIO;
    }
    if (rflags & X86_EFLAGS_ZF) 
    {
        pr_err("RELM: VMXOFF failed - VMfailValid\n");
        return -EIO;
    }
    
    pr_info("RELM: VMXOFF successful, CPU exited VMX operation\n");

    return 0;
}

static int relm_setup_vmcs_region(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    uint32_t vmcs_size = _get_vmcs_size(); 
    size_t alloc_size = (vmcs_size <= PAGE_SIZE) ? PAGE_SIZE : PAGE_ALIGN(vmcs_size); 

    vcpu->vmcs = (struct vmcs_region *)__get_free_pages(
        GFP_KERNEL | __GFP_ZERO, get_order(alloc_size)); 
    if(!vcpu->vmcs)
        return -ENOMEM; 

    *(uint32_t *)vcpu->vmcs = _vmcs_revision_id();
    vcpu->vmcs_pa = virt_to_phys(vcpu->vmcs);

    pr_info("VMCS region alllocated, revision ID set, and loaded\n"); 
    return 0;
}

int relm_vmclear(struct vcpu *vcpu)
{
    uint64_t rflags; 
    
    if(!vcpu || !vcpu->vmcs_pa)
    {
        pr_err("RELM: Invalid VMCS region\n"); 
        return -EINVAL; 
    }

    asm volatile (
        "vmclear %[pa]\n\t"
        "pushfq\n\t"
        "popq %[rflags]\n\t"
        : [rflags] "=r" (rflags)
        : [pa] "m" (vcpu->vmcs_pa)
        : "cc", "memory"
    );

    if (rflags & X86_EFLAGS_CF) 
    {
        pr_err("RELM: VMCLEAR failed - VMfailInvalid\n");
        return -EIO;
    }
    if (rflags & X86_EFLAGS_ZF) 
    {
        pr_err("RELM: VMCLEAR failed - VMfailValid\n");
        return -EIO;
    }
    
    pr_info("RELM: VMCLEAR successful for VMCS at PA 0x%llx\n", vcpu->vmcs_pa);
    return 0;
}

int relm_vmptrld(struct vcpu *vcpu)
{
    uint64_t rflags;
    
    if (!vcpu || !vcpu->vmcs_pa)
    {
        pr_err("RELM: Invalid VMCS region\n");
        return -EINVAL;
    }
    
    asm volatile (
        "vmptrld %[pa]\n\t"
        "pushfq\n\t"
        "popq %[rflags]\n\t"
        : [rflags] "=r" (rflags)
        : [pa] "m" (vcpu->vmcs_pa)
        : "cc", "memory"
    );
    
    if (rflags & X86_EFLAGS_CF) 
    {
        pr_err("RELM: VMPTRLD failed - VMfailInvalid\n");
        return -EIO;
    }
    if (rflags & X86_EFLAGS_ZF) 
    {
        pr_err("RELM: VMPTRLD failed - VMfailValid\n");
        return -EIO;
    }
    
    pr_info("RELM: VMPTRLD successful, VMCS at PA 0x%llx is now current\n", vcpu->vmcs_pa);
    return 0;
}
static struct host_cpu * relm_host_cpu_create(int logical_cpu_id)
{
    struct host_cpu * hcpu;
    int ret; 

    hcpu = kmalloc(sizeof(*hcpu), GFP_KERNEL); 
    if(!hcpu)
        return ERR_PTR(-ENOMEM); 

    hcpu->logical_cpu_id = logical_cpu_id; 

    if(relm_setup_vmxon_region(hcpu) != 0)
    {
        pr_err("failed to setup vmxon region on host cpu : %d\n", 
               hcpu->logical_cpu_id); 

        hcpu->logical_cpu_id = -1; 
        kfree(hcpu); 
        return NULL;  
    }

    ret = relm_vmxon(hcpu); 
    if(ret != 0)
    {
        pr_err("RELM: VMXON failed on CPU %d", logical_cpu_id); 
        relm_free_vmxon_region(hcpu); 
        kfree(hcpu); 
        return NULL; 
    }

    return hcpu; 
}

static void relm_destroy_host_cpu(struct host_cpu *hcpu)
{
    if(hcpu)
    {
        relm_vmxoff(hcpu); 
        relm_free_vmxon_region(hcpu); 
        kfree(hcpu); 
        hcpu = NULL; 
    }
}

static int relm_setup_cr_controls(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    uint64_t fixed0, fixed1; 
    uint64_t cr0_mask, cr4_mask; 

    /*INITIAL GUEST CR0 */ 
    fixed0 = __rdmsr1(MSR_IA32_VMX_CR0_FIXED0); 
    fixed1 = __rdmsr1(MSR_IA32_VMX_CR0_FIXED1);

    /*Initial state: paging (PG), Protected Mode (PE), Numeric Error(NE) */ 
    vcpu->cr0 = X86_CR0_PG | X86_CR0_PE | X86_CR0_NE; 

    /*hardware sanitation */ 
    vcpu->cr0 = (vcpu->cr0 | fixed0) & fixed1; 

    /*INITIAL GUEST CR4 */ 
    fixed0 = __rdmsr1(MSR_IA32_VMX_CR4_FIXED0); 
    fixed1 = __rdmsr1(MSR_IA32_VMX_CR4_FIXED1); 

    vcpu->cr4 = X86_CR4_VMXE | X86_CR4_PAE; 
    vcpu->cr4 = (vcpu->cr4 | fixed0) & fixed1; 

    /*configure host mask 
     * if bit is 1 in mask, guest cannot change it withot a vmexit
     * */

    cr0_mask = X86_CR0_PG | X86_CR0_PE | X86_CR0_NE | X86_CR0_CD | X86_CR0_NW;
    cr4_mask = X86_CR4_VMXE | X86_CR4_PAE | X86_CR4_PSE;

    CHECK_VMWRITE(GUEST_CR0, vcpu->cr0); 
    CHECK_VMWRITE(GUEST_CR4, vcpu->cr4); 
    CHECK_VMWRITE(GUEST_CR3, vcpu->cr3); 

    CHECK_VMWRITE(CR0_READ_SHADOW, vcpu->cr0); 
    CHECK_VMWRITE(CR4_READ_SHADOW, vcpu->cr4 & ~X86_CR4_VMXE); 

    CHECK_VMWRITE(CR0_GUEST_HOST_MASK, cr0_mask); 
    CHECK_VMWRITE(CR4_GUEST_HOST_MASK, cr4_mask); 

    return 0; 
}

static uint32_t relm_get_max_cr3_targets(void)
{
    uint64_t vmx_misc = __rdmsr1(MSR_IA32_VMX_MISC);
    return (uint8_t)((vmx_misc >> 16) & 0x1FF); 
}

/**
 * relm_set_cr3_target_value - write a GPA into a specific hardware slot 
 * @idx: the slot index (typically 0 to 3)
 * @target_gpa : the guest physical address of the page table root 
 */ 

static int relm_set_cr3_target_value(uint32_t idx, 
                                    uint64_t target_gpa)
{
    if(idx >= relm_get_max_cr3_targets())
        return -EINVAL; 

    switch(idx)
    {
        case 0:
            CHECK_VMWRITE(CR3_TARGET_VALUE0, target_gpa); 
            break;     
        case 1:
            CHECK_VMWRITE(CR3_TARGET_VALUE1, target_gpa); 
            break; 
        case 2:
            CHECK_VMWRITE(CR3_TARGET_VALUE2, target_gpa); 
            break; 
        case 3:
            CHECK_VMWRITE(CR3_TARGET_VALUE3, target_gpa); 
            break;

        default:
            return -ENOTSUPP; 
    }

    return 0; 
}

static int relm_set_cr3_target_count(uint32_t count)
{
    CHECK_VMWRITE(CR3_TARGET_COUNT, (uint64_t)count); 
    return 0; 
}

static int relm_init_cr3_targets(void)
{
    if(relm_set_cr3_target_count(0) != 0)
        return -1; 

    for(int i = 0; i < 4; i++)
        relm_set_cr3_target_value(i, 0); 

    return 0; 
}

/*which IO operation */ 
static int relm_setup_io_bitmap(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL;

    size_t total_bitmap_size = 2 * VMCS_IO_BITMAP_SIZE;

    vcpu->io_bitmap = (uint8_t *)__get_free_pages(GFP_KERNEL,
                                                   get_order(total_bitmap_size));
    if(!vcpu->io_bitmap)
    {
        pr_err("Failed to allocate I/O bitmap memory\n"); 
        return -ENOMEM; 
    }

    /* clear entire I/O bitmap (all 0  == allow all ports) */ 
    memset(vcpu->io_bitmap, 0, total_bitmap_size);

    vcpu->io_bitmap_pa = virt_to_phys(vcpu->io_bitmap); 
    
    PDEBUG("Allocated and cleared I/O bitmap at VA %p PA 0x%llx\n", 
            vcpu->io_bitmap, (unsigned long long )vcpu->io_bitmap_pa);

    /*write the address to the VMCS */ 
    if(_vmwrite(VMCS_IO_BITMAP_A, vcpu->io_bitmap_pa) != 0)
    {
        PDEBUG("VMWrite VMCS_IO_BITMAP_A failed\n");
        relm_free_io_bitmap(vcpu); 
        return -EIO; 
    }

    if(_vmwrite(VMCS_IO_BITMAP_B, vcpu->io_bitmap_pa + VMCS_IO_BITMAP_SIZE) != 0)
    {
        PDEBUG("VMWrite VMCS_IO_BITMAP_B failed\n"); 
        relm_free_io_bitmap(vcpu); 
        return -EIO; 
    }

    PDEBUG("IO bitmap A physical address : 0x%llx\nIO bitmap B physical address : 0x%llx\n", 
           vcpu->io_bitmap_pa, 
           vcpu->io_bitmap_pa + VMCS_IO_BITMAP_SIZE); 

    return 0; 

}

static int relm_update_exception_bitmap(struct vcpu *vcpu)
{
    CHECK_VMWRITE(VMCS_EXCEPTION_BITMAP, (vcpu->exception_bitmap & 0xFFFFFFFF)); 
    return 0; 
}

static int relm_set_exception_intercept(struct vcpu *vcpu, int vector)
{
    int ret;
    if(vector >= 32)
        ret = -EINVAL; 

    vcpu->exception_bitmap |= (1U << vector); 
    ret = relm_update_exception_bitmap(vcpu); 

    return ret; 
}

static int relm_clear_exception_intercept(struct vcpu *vcpu, int vector) 
{
    int ret;
    if(vector >= 32)
        ret = -EINVAL;

    vcpu->exception_bitmap &= ~(1U << vector); 
    ret = relm_update_exception_bitmap(vcpu); 

    return ret;  
}

/*MSRs that cause VM exit when accessed by guest */ 
static int relm_setup_msr_bitmap(struct vcpu *vcpu)
{
    vcpu->msr_bitmap = (uint8_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if(!vcpu->msr_bitmap)
    {
        pr_info("Failed to allocate MSR bitmap\n"); 
        return -ENOMEM;
    }

    vcpu->msr_bitmap_pa = virt_to_phys(vcpu->msr_bitmap); 

    /*mark IA32_SYSENTER_CS as causing a VM exit */ 
    uint32_t msr_index = IA32_SYSENTER_CS;
    uint8_t *bitmap = (uint8_t*)vcpu->msr_bitmap;
    uint32_t byte = msr_index / 8;
    uint8_t bit = msr_index % 8; 
    bitmap[byte] |= (1 << bit); 


    if(_vmwrite(VMCS_MSR_BITMAP, vcpu->msr_bitmap_pa) != 0){
        relm_free_msr_bitmap(vcpu); 
        return -EIO; 
    }

    return 0; 
}

/*util round size up to full pagess and computer order */ 
static inline unsigned int msr_area_order(size_t bytes)
{
    size_t pages  = DIV_ROUND_UP(bytes, PAGE_SIZE); 
    return get_order(pages * PAGE_SIZE); 
}

static struct msr_entry *alloc_msr_entry(size_t n_entries)
{
    size_t size = n_entries * sizeof(struct msr_entry); 
    unsigned int order = msr_area_order(size); 

    struct page *p = alloc_pages(GFP_KERNEL | __GFP_ZERO, order); 
    if(!p)
        return ERR_PTR(-ENOMEM); 

    return (struct msr_entry*)page_address(p); 
}

static void free_msr_area(struct msr_entry *area, size_t n_entries)
{
    if(!area)
        return; 

    size_t size = n_entries * sizeof(struct msr_entry); 
    unsigned int order = msr_area_order(size); 
    free_pages((unsigned long)area, order); 
}

/*populate msr-load are from parallel arrays */ 
static void populate_msr_load_area(struct msr_entry *area, size_t count,
                              const uint32_t *indices, const uint64_t *values)
{
    size_t i; 
    for(i = 0; i < count; ++i)
    {
        area[i].index = indices[i]; 
        area[i].reserved = 0; 
        area[i].value = values[i]; 
    }

}

/*populate MSR-store areas index fields. CPU will write this values on VM-exit */ 
static void populate_msr_store_area(struct msr_entry *area, size_t count, 
                                    const uint32_t *indices)
{
    size_t i;
    for(i = 0; i < count; ++i)
    {
        area[i].index = indices[i];
        area[i].reserved = 0; 
        area[i].value = 0; 
    }

}

static int relm_setup_msr_areas(struct vcpu *vcpu,
                    const uint32_t *vmexit_list,  size_t vmexit_count,
                    const uint32_t *vmentry_list, const uint64_t *vmentry_values,
                    size_t vmentry_count)
{
    int rc = 0;
    size_t i;

    if (!vcpu)
        return -EINVAL;

    #ifndef UINT16_MAX
    #define UINT16_MAX 65535
    #endif 

    /* VMCS count fields are 16-bit */
    if (vmexit_count > UINT16_MAX || vmentry_count > UINT16_MAX)
        return -EINVAL; 

    /*VM-exit MSR-store area (guest MSRs → memory on exit) */
    vcpu->vmexit_store_area = alloc_msr_entry(vmexit_count);
    if (IS_ERR(vcpu->vmexit_store_area)) 
    {
        rc = PTR_ERR(vcpu->vmexit_store_area); 
        vcpu->vmexit_store_area = NULL; 
        goto _out;
    }
    vcpu->vmexit_store_pa = virt_to_phys(vcpu->vmexit_store_area);

    /* VM-exit MSR-load area (memory → host MSRs on exit) */
    vcpu->vmexit_load_area = alloc_msr_entry(vmentry_count);
    if (IS_ERR(vcpu->vmexit_load_area))
    {
        rc = PTR_ERR(vcpu->vmexit_load_area); 
        vcpu->vmexit_load_area = NULL; 
        goto _out_free_exit_store;
    }
    vcpu->vmexit_load_pa = virt_to_phys(vcpu->vmexit_load_area);

    /* VM-entry MSR-load area (memory → guest MSRs on entry) */
    vcpu->vmentry_load_area = alloc_msr_entry(vmentry_count);
    if (IS_ERR(vcpu->vmentry_load_area))
    {
        rc = PTR_ERR(vcpu->vmentry_load_area); 
        vcpu->vmentry_load_area = NULL; 
        goto _out_free_exit_load;
    }
    vcpu->vmentry_load_pa = virt_to_phys(vcpu->vmentry_load_area);

    populate_msr_store_area(vcpu->vmexit_store_area, vmexit_count, vmexit_list);

    /* On VM-exit, restore host MSR values (typically the ones the guest sees on entry) */
    for (i = 0; i < vmentry_count; ++i) 
    {
        uint32_t idx = vmentry_list[i];
        uint64_t val = vmentry_values ? vmentry_values[i] : 0;

        vcpu->vmexit_load_area[i].index    = idx;
        vcpu->vmexit_load_area[i].reserved = 0;
        vcpu->vmexit_load_area[i].value    = val;
    }

    populate_msr_load_area(vcpu->vmentry_load_area,
                           vmentry_count,
                           vmentry_list,
                           vmentry_values);

    vcpu->vmexit_count  = vmexit_count;
    vcpu->vmentry_count = vmentry_count;

    if (_vmwrite(VMCS_EXIT_MSR_STORE_ADDR, vcpu->vmexit_store_pa) ||
        _vmwrite(VMCS_EXIT_MSR_STORE_COUNT, (uint64_t)vmexit_count) ||
        _vmwrite(VMCS_EXIT_MSR_LOAD_ADDR,   vcpu->vmexit_load_pa) ||
        _vmwrite(VMCS_EXIT_MSR_LOAD_COUNT,  (uint64_t)vmentry_count) ||
        _vmwrite(VMCS_ENTRY_MSR_LOAD_ADDR,  vcpu->vmentry_load_pa) ||
        _vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, (uint64_t)vmentry_count)) 
    {
        rc = -EIO;
        goto _out_free_all;
    }

    return 0;

_out_free_all:
    free_msr_area(vcpu->vmentry_load_area, vmentry_count);
    vcpu->vmentry_load_area = NULL;
    vcpu->vmentry_load_pa = 0;

_out_free_exit_load:
    free_msr_area(vcpu->vmexit_load_area, vmentry_count);
    vcpu->vmexit_load_area = NULL;
    vcpu->vmexit_load_pa = 0;

_out_free_exit_store:
    free_msr_area(vcpu->vmexit_store_area, vmexit_count);
    vcpu->vmexit_store_area = NULL;
    vcpu->vmexit_store_pa = 0;

_out:
    return rc;
}

void relm_free_all_msr_areas(struct vcpu *vcpu)
{
    if (!vcpu)
        return;

    if (vcpu->vmexit_store_area)
    {
        free_msr_area(vcpu->vmexit_store_area, vcpu->vmexit_count);
        vcpu->vmexit_store_area = NULL;
        vcpu->vmexit_store_pa = 0;
    }

    if (vcpu->vmexit_load_area) 
    {
        free_msr_area(vcpu->vmexit_load_area, vcpu->vmentry_count);
        vcpu->vmexit_load_area = NULL;
        vcpu->vmexit_load_pa = 0;
    }

    if (vcpu->vmentry_load_area) 
    {
        free_msr_area(vcpu->vmentry_load_area, vcpu->vmentry_count);
        vcpu->vmentry_load_area = NULL;
        vcpu->vmentry_load_pa = 0;
    }

    vcpu->vmexit_count = vcpu->vmentry_count = 0;
}

static int relm_vcpu_setup_msr_state(struct vcpu *vcpu)
{
    uint64_t vmentry_values[RELM_MAX_MANAGED_MSRS] = {0};
    int i = 0; 

    vcpu->msr_indices[i++] = MSR_IA32_EFER;
    vcpu->msr_indices[i++] = MSR_IA32_STAR;
    vcpu->msr_indices[i++] = MSR_IA32_LSTAR;
    vcpu->msr_indices[i++] = MSR_IA32_CSTAR;
    vcpu->msr_indices[i++] = MSR_IA32_FMASK;
    vcpu->msr_indices[i++] = MSR_IA32_FS_BASE;
    vcpu->msr_indices[i++] = MSR_IA32_GS_BASE;
    vcpu->msr_count = i;

    /*prepare guest initial values for vm-entry 
     * default: long mode (LME/LMA) and syscall enable */ 
    vcpu->efer = EFER_LME | EFER_LMA | EFER_SCE;

    vmentry_values[0] = vcpu->efer;          // Guest EFER
    vmentry_values[1] = 0;                  // Guest STAR
    vmentry_values[2] = 0;                  // Guest LSTAR
    vmentry_values[3] = 0;                  // Guest CSTAR
    vmentry_values[4] = 0;                  // Guest FMASK
    vmentry_values[5] = vcpu->regs.fs_base;      // Guest FS_BASE
    vmentry_values[6] = vcpu->regs.gs_base;      // Guest GS_BASE
    

    return relm_setup_msr_areas(vcpu, 
                               vcpu->msr_indices, vcpu->msr_count,
                               vcpu->msr_indices, vmentry_values, 
                               vcpu->msr_count); 
}

static void relm_init_exec_controls(struct vcpu *vcpu)
{
    struct vmx_exec_ctrls *controls = &vcpu->controls; 

    controls->pin_based = 
        VMCS_PIN_EXTINT_EXITING | 
        VMCS_PIN_NMI_EXITING  | 
        VMCS_PIN_VIRTUAL_NMIS |
        VMCS_PIN_PREEMPT_TIMER | 
        VMCS_PIN_POSTED_INTRS; 
    
    controls->primary_proc = 
        VMCS_PROC_USE_MSR_BITMAPS | 
        VMCS_PROC_ACTIVATE_SECONDARY |
        VMCS_PROC_HLT_EXITING |
        VMCS_PROC_CR8_LOAD_EXITING | 
        VMCS_PROC_CR8_STORE_EXITING |
        VMCS_PROC_TPR_SHADOW |
        VMCS_PROC_UNCOND_IO_EXITING |
        VMCS_PROC_USE_IO_BITMAPS; 

    controls->secondary_proc = 
        VMCS_PROC2_ENABLE_EPT |
        VMCS_PROC2_RDTSCP | 
        VMCS_PROC2_UNRESTRICTED_GUEST |
        VMCS_PROC2_ENABLE_VMFUNC; 

    if(_cpu_has_vpid())
        controls->secondary_proc = 
            controls->secondary_proc | VMCS_PROC2_VPID; 

    controls->vm_entry =
        VM_ENTRY_IA32E_MODE |
        VMCS_ENTRY_LOAD_GUEST_PAT | 
        VMCS_ENTRY_LOAD_IA32_EFER | 
        VMCS_ENTRY_LOAD_DEBUG; 

    controls->vm_exit = 
        VM_EXIT_HOST_ADDR_SPACE_SIZE | 
        VMCS_EXIT_SAVE_IA32_PAT |
        VMCS_EXIT_LOAD_IA32_PAT |
        VMCS_EXIT_SAVE_EFER |
        VMCS_EXIT_LOAD_EFER | 
        VMCS_EXIT_ACK_INTR_ON_EXIT; 
}

static int relm_apply_exec_controls(struct vcpu *vcpu)
{
    struct vmx_exec_ctrls *controls = &vcpu->controls; 
    uint64_t msr; 
    uint32_t allowed0; 
    uint32_t allowed1; 
    uint32_t final; 

    /*pin-based */ 
    msr = __rdmsr1(MSR_IA32_VMX_PINBASED_CTLS); 
    allowed0 = (uint32_t)(msr & 0xFFFFFFFF); 
    allowed1 = (uint32_t)(msr >> 32);

    final = (controls->pin_based | allowed1) & (allowed0 | allowed1); 
    CHECK_VMWRITE(VMCS_PIN_BASED_EXEC_CONTROLS, final); 

    /*primary processor-based*/
    msr = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS); 
    allowed0 = (uint32_t)(msr & 0xFFFFFFFF); 
    allowed1 = (uint32_t)(msr >> 32); 

    final = (controls->primary_proc | allowed1) & (allowed0 | allowed1); 
    CHECK_VMWRITE(VMCS_PRIMARY_PROC_BASED_EXEC_CONTROLS, final);

    /*secondary processor-based */ 
    msr = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS2); 
    allowed0 = (uint32_t)(msr & 0xFFFFFFFF); 
    allowed1 = (uint32_t)(msr >> 32); 

    final = (controls->secondary_proc | allowed1) & (allowed0 | allowed1); 
    CHECK_VMWRITE(VMCS_SECONDARY_PROC_BASED_EXEC_CONTROLS, final);

    /*vm-entry contols */ 
    msr = __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS); 
    allowed0 = (uint32_t)(msr & 0xFFFFFFFF); 
    allowed1 = (uint32_t)(msr >> 32); 

    final = (controls->vm_entry | allowed1) & (allowed0 | allowed1); 
    CHECK_VMWRITE(VMCS_ENTRY_CONTROLS, final); 

    msr = __rdmsr1(MSR_IA32_VMX_EXIT_CTLS); 
    allowed0 = (uint32_t)(msr & 0xFFFFFFFF); 
    allowed1 = (uint32_t)(msr >> 32); 

    final = (controls->vm_exit | allowed1) & (allowed0 | allowed1); 
    CHECK_VMWRITE(VMCS_EXIT_CONTROLS, final); 

    return 0 ; 
}

int relm_setup_exec_controls(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    relm_init_exec_controls(vcpu); 
    if(relm_apply_exec_controls(vcpu) != 0)
        return -1; 

    return 0; 

}

struct vcpu *relm_vcpu_alloc_init(struct relm_vm *vm, int vpid)
{
    if(!vm)
        return ERR_PTR(-EINVAL); 

    struct vcpu *vcpu;
    struct host_cpu *hcpu; 
    int ret; 

    PDEBUG("RELM: Allocating zeroed VCPU struct\n");
    /* Allocate zeroed VCPU struct */
    vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL);
    if (!vcpu) {
        PDEBUG("RELM: Failed to allocate VCPU struct\n");
        return ERR_PTR(-ENOMEM);
    }
    PDEBUG("RELM: VCPU struct allocated at %p\n", vcpu);

    vcpu->vm = vm;
    vcpu->vpid = vpid;
    vcpu->state = VCPU_STATE_UNINITIALIZED; 
    vcpu->halted = false; 

    /*default architectural state */ 
    vcpu->regs.rflags = 0x2; 
    vcpu->regs.rip = 0x0; 

    /*cr3 points to guest page tables */
    vcpu->cr3 = vm->pml4_gpa;

    PDEBUG("RELM: Initializing spinlock and waitqueue\n");
    /* Initialize spinlock */
    spin_lock_init(&vcpu->lock);
    init_waitqueue_head(&vcpu->wq); 

    PDEBUG("RELM: Allocating host CPU structure\n");
    hcpu = relm_host_cpu_create(HOST_CPU_ID); 
    if(IS_ERR_OR_NULL(hcpu)) {
        PDEBUG("RELM: Failed to create host CPU\n");
        goto _out_free_vcpu; 
    }
    PDEBUG("RELM: Host CPU allocated: hcpu=%p\n", hcpu);

    vcpu->hcpu = hcpu; 
    vcpu->target_cpu_id = hcpu->logical_cpu_id; 

    PDEBUG("RELM: Allocating vCPU host stack\n");
    /*alllocate vCPU stack */ 
    vcpu->host_stack = (void *)__get_free_pages(
        GFP_KERNEL | __GFP_ZERO, 
        HOST_STACK_ORDER
    ); 
    if(!vcpu->host_stack) {
        PDEBUG("RELM: Failed to allocate host stack\n");
        goto _out_free_host_cpu; 
    }
    PDEBUG("RELM: Host stack allocated at %p\n", vcpu->host_stack);

    /*point to top of host stack */ 
    uint64_t top = (uint64_t)vcpu->host_stack + (PAGE_SIZE << HOST_STACK_ORDER); 
    top -= ~0x100; 
    top &= ~0xFULL; 

    vcpu->host_rsp = top; 

    PDEBUG("RELM: Host RSP set to 0x%llx\n", vcpu->host_rsp);

    PDEBUG("RELM: Setting up VMCS region\n");
    /* Allocate and setup VMCS region */
    if (relm_setup_vmcs_region(vcpu) != 0)
    {
        pr_err("RELM: Failed to setup VMCS region\n");
        goto _out_free_host_stack; 
    }
    PDEBUG("RELM: VMCS region setup complete\n");

    PDEBUG("RELM: Performing VMCLEAR\n");
    ret = relm_vmclear(vcpu); 
    PDEBUG("RELM: VMCLEAR returned %d\n", ret);
    if(ret != 0)
    {
        pr_err("RELM: VMCLEAR failed\n"); 
        goto _out_free_vmcs; 
    }

    PDEBUG("RELM: Performing VMPTRLD\n");
    ret = relm_vmptrld(vcpu);
    PDEBUG("RELM: VMPTRLD returned %d\n", ret);
    if(ret != 0)
    {
        pr_err("RELM: VMPTRLD failed\n"); 
        goto _out_free_vmcs; 
    }

    if(vm->ept){
        PDEBUG("RELM: Writing EPT_POINTER to VMCS: 0x%llx\n", vm->ept->eptp);
        CHECK_VMWRITE(EPT_POINTER, vm->ept->eptp); 
    }else{
        pr_err("RELM: No EPT POINTER - cannot continue\n"); 
        goto _out_free_vmcs; 
    }

    PDEBUG("RELM: Setting up VMX execution controls\n");
    if(relm_setup_exec_controls(vcpu) != 0)
    {
        pr_err("RELM: Failed to setup VMX execution controls\n"); 
        goto _out_free_vmcs;  
    }

    if(_cpu_has_vpid())
    {
        uint64_t vpid = vcpu->vpid; 
        PDEBUG("RELM: CPU has VPID, writing VMCS_VPID: %llu\n", vpid);
        CHECK_VMWRITE(VMCS_VPID, vpid); 
    }

    PDEBUG("RELM: Setting up IO bitmap\n");
    /* Setup IO bitmap */
    if(relm_vcpu_io_bitmap_enabled(vcpu))
    {
        if (relm_setup_io_bitmap(vcpu) != 0)
        {
            pr_err("Failed to setup I/O bitmap\n");
            goto _out_free_msr_areas; 
        }
    }

    PDEBUG("RELM: Setting exception bitmap\n");
    /* we catch #UD (6) to prevent guest crashes on unsupported instructions.
     * we catch #PF (14) if we are using Shadow Paging or debugging memory.
     */
    vcpu->exception_bitmap = (1U << 6) | (1U << 14); 

    PDEBUG("RELM: Setting up MSR bitmap\n");
    /* Setup MSR bitmap */
    if(relm_vcpu_msr_bitmap_enabled(vcpu))
    {
        if (relm_setup_msr_bitmap(vcpu) != 0) 
        {
            pr_err("Failed to setup MSR bitmap\n");
            goto _out_free_io_bitmap; 
        }
    }

    PDEBUG("RELM: Setting up MSR state\n");
    if(relm_vcpu_setup_msr_state(vcpu) != 0)
    {
        pr_err("Failed to setup MSR areas\n"); 
        goto _out_free_msr_bitmap; 
    }

    PDEBUG("RELM: VCPU allocation and initialization complete\n");
    return vcpu; 

_out_free_msr_bitmap:
    relm_free_msr_bitmap(vcpu);

_out_free_io_bitmap:
    relm_free_io_bitmap(vcpu);

_out_free_msr_areas:
    relm_free_all_msr_areas(vcpu);

_out_free_vmcs:
    relm_free_vmcs_region(vcpu);

_out_free_host_stack:
    free_pages((unsigned long)vcpu->host_stack, HOST_STACK_ORDER);

_out_free_host_cpu:
    relm_destroy_host_cpu(vcpu->hcpu); 
    
_out_free_vcpu:
    kfree(vcpu);
    return NULL; 
}

void relm_free_io_bitmap(struct vcpu *vcpu)
{
    if(!vcpu)
        return;

    if (vcpu->io_bitmap) 
    {
        free_pages((unsigned long)vcpu->io_bitmap, VMCS_IO_BITMAP_PAGES_ORDER);
        vcpu->io_bitmap = NULL;
        vcpu->io_bitmap_pa = 0;
    }
}

void relm_free_msr_bitmap(struct vcpu *vcpu)
{
    if(!vcpu)
        return; 

    if (vcpu->msr_bitmap) 
    {
        free_page((unsigned long)vcpu->msr_bitmap);
        vcpu->msr_bitmap = NULL;
        vcpu->msr_bitmap_pa = 0;
    }
}

void relm_free_vmcs_region(struct vcpu *vcpu)
{
    if (vcpu->vmcs) 
    {
        free_pages((unsigned long)vcpu->vmcs, get_order(_get_vmcs_size()));
        vcpu->vmcs = NULL;
        vcpu->vmcs_pa = 0;
    }
}

static void relm_free_vmxon_region(struct host_cpu *hcpu)
{
    if (hcpu->vmxon) 
    {
        free_pages((unsigned long)hcpu->vmxon, 0); // VMXON is 1 page
        hcpu->vmxon = NULL;
        hcpu->vmxon_pa = 0;
    }
}

/* Free the entire VCPU */
void relm_free_vcpu(struct vcpu *vcpu)
{
    if (!vcpu)
        return;

    relm_free_io_bitmap(vcpu);
    relm_free_msr_bitmap(vcpu);
    relm_free_vmcs_region(vcpu);
    relm_destroy_host_cpu(vcpu->hcpu); 
    kfree(vcpu);
}

static int relm_setup_host_state(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    u64 cr0 = _read_cr0();
    u64 cr3 = _read_cr3();
    u64 cr4 = _read_cr4();

    CHECK_VMWRITE(HOST_CR0, cr0);
    CHECK_VMWRITE(HOST_CR3, cr3);
    CHECK_VMWRITE(HOST_CR4, cr4);

    extern void relm_vmexit_handler(void); 
    CHECK_VMWRITE(HOST_RSP, vcpu->host_rsp);
    CHECK_VMWRITE(HOST_RIP, (uint64_t)relm_vmexit_handler);

    /* Segment selectors (must be valid) 
     * masking with 0xF8 ensures bottom 3 bits (RPL and TI) are 0*/
    CHECK_VMWRITE(HOST_CS_SELECTOR, __KERNEL_CS & 0xF8);
    CHECK_VMWRITE(HOST_SS_SELECTOR, __KERNEL_DS & 0xF8);
    CHECK_VMWRITE(HOST_DS_SELECTOR, __KERNEL_DS & 0xF8);
    CHECK_VMWRITE(HOST_ES_SELECTOR, __KERNEL_DS & 0xF8);
    CHECK_VMWRITE(HOST_FS_SELECTOR, 0);
    CHECK_VMWRITE(HOST_GS_SELECTOR, 0);
    
    u16 tr; 
    struct desc_ptr gdt; 
    unsigned long tr_base; 

    /*read TR selector */ 
    __asm__ __volatile__ (
        "str %0" 
        : "=r"(tr)); 

    /*read GDT*/ 
    __asm__ __volatile__ (
            "sgdt %0"
            : "=m"(gdt)); 

    /*calculate TR base from GDT*/ 
    if(tr)
    {
        struct desc_struct *gdt_desc= (struct desc_struct*)gdt.address; 
        unsigned int index = tr >> 3; 
        
        tr_base = gdt_desc[index].base0 |
            (gdt_desc[index].base1 << 16) |
            (gdt_desc[index].base2 << 24); 
    
        #ifdef CONFIG_X86_64
        /*for 64 bit TSS descriptor is 16 bytes*/  
        if(index + 1 < (gdt.size + 1) / 8)
        {
            unsigned long base_high = *(unsigned long *)&gdt_desc[index + 1]; 
            tr_base |= (base_high << 32);
        }
        #endif
    }
    else {
        pr_err("RELM: TR selector is 0, cannot continue\n"); 
        return -EINVAL; 
    }

    CHECK_VMWRITE(HOST_TR_SELECTOR, tr & 0xFFF8); 
    CHECK_VMWRITE(HOST_TR_BASE, tr_base); 
    CHECK_VMWRITE(HOST_GDTR_BASE, gdt.address); 

    struct desc_ptr idt; 
    __asm__ __volatile__ (
        "sidt %0"
        : "=m"(idt));

    CHECK_VMWRITE(HOST_IDTR_BASE, idt.address); 

    CHECK_VMWRITE(VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFULL);
    /* FS/GS base */
    CHECK_VMWRITE(HOST_FS_BASE, __rdmsr1(MSR_FS_BASE));
    CHECK_VMWRITE(HOST_GS_BASE, __rdmsr1(MSR_GS_BASE));

    /* Syscall MSRs */
    CHECK_VMWRITE(HOST_SYSENTER_CS, __rdmsr1(MSR_IA32_SYSENTER_CS));
    CHECK_VMWRITE(HOST_SYSENTER_ESP, __rdmsr1(MSR_IA32_SYSENTER_ESP));
    CHECK_VMWRITE(HOST_SYSENTER_EIP, __rdmsr1(MSR_IA32_SYSENTER_EIP));

    /* EFER must be set */
    CHECK_VMWRITE(HOST_IA32_EFER, __rdmsr1(MSR_EFER));

    return 0; 
}

static int relm_setup_guest_state(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    /* Control registers */
    CHECK_VMWRITE(GUEST_CR0, vcpu->cr0);
    CHECK_VMWRITE(GUEST_CR3, vcpu->cr3);
    CHECK_VMWRITE(GUEST_CR4, vcpu->cr4);

    /* RIP / RSP / RFLAGS */
    CHECK_VMWRITE(GUEST_RIP, vcpu->regs.rip);
    CHECK_VMWRITE(GUEST_RSP, vcpu->regs.rsp);
    CHECK_VMWRITE(GUEST_RFLAGS, 0x2); /* reserved bit must be 1 */

    /* Segment selectors (flat) */
    CHECK_VMWRITE(GUEST_CS_SELECTOR, 0x8);
    CHECK_VMWRITE(GUEST_DS_SELECTOR, 0x10);
    CHECK_VMWRITE(GUEST_ES_SELECTOR, 0x10);
    CHECK_VMWRITE(GUEST_SS_SELECTOR, 0x10);
    CHECK_VMWRITE(GUEST_FS_SELECTOR, 0);
    CHECK_VMWRITE(GUEST_GS_SELECTOR, 0);

    /* Segment bases */
    CHECK_VMWRITE(GUEST_CS_BASE, 0);
    CHECK_VMWRITE(GUEST_DS_BASE, 0);
    CHECK_VMWRITE(GUEST_ES_BASE, 0);
    CHECK_VMWRITE(GUEST_SS_BASE, 0);
    CHECK_VMWRITE(GUEST_FS_BASE, 0);
    CHECK_VMWRITE(GUEST_GS_BASE, 0);

    /* Segment limits */
    CHECK_VMWRITE(GUEST_CS_LIMIT, 0xFFFFFFFF);
    CHECK_VMWRITE(GUEST_DS_LIMIT, 0xFFFFFFFF);
    CHECK_VMWRITE(GUEST_ES_LIMIT, 0xFFFFFFFF);
    CHECK_VMWRITE(GUEST_SS_LIMIT, 0xFFFFFFFF);

    /* Segment access rights (64-bit code/data) */
    CHECK_VMWRITE(GUEST_CS_AR_BYTES, 0xA09B);
    CHECK_VMWRITE(GUEST_DS_AR_BYTES, 0xC093);
    CHECK_VMWRITE(GUEST_ES_AR_BYTES, 0xC093);
    CHECK_VMWRITE(GUEST_SS_AR_BYTES, 0xC093);

    CHECK_VMWRITE(GUEST_FS_AR_BYTES, 0x10000);  // Unusable
    CHECK_VMWRITE(GUEST_GS_AR_BYTES, 0x10000);  // Unusable

    CHECK_VMWRITE(GUEST_LDTR_SELECTOR, 0);
    CHECK_VMWRITE(GUEST_LDTR_BASE, 0);
    CHECK_VMWRITE(GUEST_LDTR_LIMIT, 0);
    CHECK_VMWRITE(GUEST_LDTR_AR_BYTES, 0x10000); 
    
    CHECK_VMWRITE(GUEST_TR_SELECTOR, 0);
    CHECK_VMWRITE(GUEST_TR_BASE, 0);
    CHECK_VMWRITE(GUEST_TR_LIMIT, 0x67);  // Minimum TSS size
    CHECK_VMWRITE(GUEST_TR_AR_BYTES, 0x008B);  // Present, Type=TSS Busy
    
    /* GDTR / IDTR */
    CHECK_VMWRITE(GUEST_GDTR_BASE, vcpu->gdtr_base);
    CHECK_VMWRITE(GUEST_GDTR_LIMIT, vcpu->gdtr_limit);
    CHECK_VMWRITE(GUEST_IDTR_BASE, vcpu->idtr_base);
    CHECK_VMWRITE(GUEST_IDTR_LIMIT, vcpu->idtr_limit);

    /* MSRs */
    CHECK_VMWRITE(GUEST_IA32_EFER, vcpu->efer);

    CHECK_VMWRITE(GUEST_ACTIVITY_STATE, 0); 
    CHECK_VMWRITE(GUEST_INTERRUPTIBILITY_INFO, 0); 
    CHECK_VMWRITE(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    CHECK_VMWRITE(VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFULL);
    return 0; 
}

int relm_init_vmcs_state(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    int ret;

    if((ret = relm_setup_host_state(vcpu)) != 0)
    {
        pr_err("Host state setup faile : err %d\n", ret); 
        return -1; 
    }
    if((ret = relm_setup_guest_state(vcpu)) != 0)
    {
        pr_err("Guest state setup failed : err %d\n", ret); 
        return -1; 
    }

    return 0; 
}

void relm_dump_vcpu(struct vcpu *vcpu)
{
    pr_info("\n*** Guest State ***\n\n");     

    pr_info("CR0: actual=0x%lx, shadow=0x%lx, mask=0x%lx\n",
            (unsigned long)__vmread(GUEST_CR0),
            (unsigned long)__vmread(CR0_READ_SHADOW), 
            (unsigned long)__vmread(CR0_GUEST_HOST_MASK)); 

    pr_info("CR4: actual=0x%lx, shadow=0x%lx, mask=0x%lx\n", 
            (unsigned long)__vmread(GUEST_CR4), 
            (unsigned long)__vmread(CR4_READ_SHADOW), 
            (unsigned long)__vmread(CR4_GUEST_HOST_MASK)); 

    pr_info("CR3: 0x%llx\n", (unsigned long)__vmread(GUEST_CR3));

    if((vcpu->controls.secondary_proc & VMCS_PROC2_ENABLE_EPT) &&
       (__vmread(GUEST_CR4) & X86_CR4_PAE) && 
        !(vcpu->controls.vm_entry & VM_ENTRY_IA32E_MODE))
    {
        pr_info("PDPTE0 = 0x%lx PDPTE1 = 0x%lx\n",
                (unsigned long)__vmread(GUEST_PDPTE(0)),
                (unsigned long)__vmread(GUEST_PDPTE(1))); 

        pr_info("PDPTE2 = 0x%lx PDPTE3 = 0x%lx\n", 
                (unsigned long)__vmread(GUEST_PDPTE(2)),
                (unsigned long)__vmread(GUEST_PDPTE(3))); 
    }

    pr_info("RSP = 0x%lx (0x%lx) RIP = 0x%lx (0x%lx)\n", 
            (unsigned long)__vmread(GUEST_RSP), 
            (unsigned long)vcpu->regs.rsp, 
            (unsigned long)__vmread(GUEST_RIP),
            (unsigned long)vcpu->regs.rip); 

    pr_info("RFLAGS=0x%lx (0x%lx) DR7 = 0x%lx\n", 
            (unsigned long)__vmread(GUEST_RFLAGS), 
            (unsigned long)vcpu->regs.rflags, 
            (unsigned long)__vmread(GUEST_DR7)); 

    pr_info("Sysenter RSP=0x%llx CS:RIP=0x%04:0x%llx\n", 
            (unsigned long)(__vmread(GUEST_SYSENTER_ESP) & 0xFFFFFFFF), 
            (unsigned long)__vmread(GUEST_SYSENTER_CS), 
            (unsigned long)(__vmread(GUEST_SYSENTER_EIP) & 0xFFFFFFFF)); 

    
   
    pr_info("\n*** Host State ***\n\n");

    pr_info("RIP = 0x%016llx (%ps)  RSP = 0x%016llx\n",
        __vmread(HOST_RIP),
        (void *)__vmread(HOST_RIP),
        __vmread(HOST_RSP));

    pr_info("CS=%04x SS=%04x DS=%04x ES=%04x FS=%04x GS=%04x TR=%04x\n",
        (u16)__vmread(HOST_CS_SELECTOR),
        (u16)__vmread(HOST_SS_SELECTOR),
        (u16)__vmread(HOST_DS_SELECTOR),
        (u16)__vmread(HOST_ES_SELECTOR),
        (u16)__vmread(HOST_FS_SELECTOR),
        (u16)__vmread(HOST_GS_SELECTOR),
        (u16)__vmread(HOST_TR_SELECTOR));

    pr_info("FSBase=0x%016llx GSBase=0x%016llx TRBase=0x%016llx\n",
        __vmread(HOST_FS_BASE),
        __vmread(HOST_GS_BASE),
        __vmread(HOST_TR_BASE));

    pr_info("GDTBase=0x%016llx IDTBase=0x%016llx\n",
        __vmread(HOST_GDTR_BASE),
        __vmread(HOST_IDTR_BASE));

    pr_info("CR0=0x%016llx CR3=0x%016llx CR4=0x%016llx\n",
        __vmread(HOST_CR0),
        __vmread(HOST_CR3),
        __vmread(HOST_CR4));

    pr_info("Sysenter ESP=0x%08x CS:EIP=%04x:0x%08x\n",
        (u32)__vmread(HOST_SYSENTER_ESP),
        (u32)__vmread(HOST_SYSENTER_CS),
        (u32)__vmread(HOST_SYSENTER_EIP));

    if (__vmread(VMCS_EXIT_CONTROLS) &
        (VMCS_EXIT_LOAD_EFER | VMCS_EXIT_LOAD_IA32_PAT)) {
        pr_info("EFER=0x%016llx PAT=0x%016llx\n",
            __vmread(HOST_IA32_EFER),
            __vmread(HOST_IA32_PAT));
    }

    if (__vmread(VMCS_EXIT_CONTROLS) &
        VM_EXIT_LOAD_PERF_GLOBAL_CTRL){
        pr_info("PerfGlobalCtrl=0x%016llx\n",
            __vmread(HOST_IA32_PERF_GLOBAL_CTRL));
    }
    
 
}
