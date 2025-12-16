#include <cerrno>
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
#include <asm/processor.h>
#include <asm/msr.h>
#include <stdint.h>
#include <string.h>

#include "hw.h"
#include "vmcs.h"
#include "vmx_ops.h"
#include "vmx_consts.h"
#include "../utils/utils.h"

static int kvx_setup_vmxon_region(struct host_cpu *hcpu);
static int kvx_setup_vmcs_region(struct vcpu *vcpu);
static int kvx_setup_io_bitmap(struct vcpu *vcpu);
static int kvx_setup_msr_bitmap(struct vcpu *vcpu);
static int kvx_setup_msr_areas(struct vcpu *vcpu,
                               const uint32_t *vmexit_list,  size_t vmexit_count,
                               const uint32_t *vmentry_list, const uint32_t *vmentry_values,
                               size_t vmentry_count);

static int kvx_vcpu_setup_msr_state(struct vcpu *vcpu);
static int kvx_setup_exec_controls(struct vcpu *vcpu);
static int vmx_apply_exec_controls(struct vcpu *vcpu);
static void vmx_init_exec_controls(struct vcpu *vcpu);

static void kvx_free_io_bitmap(struct vcpu *vcpu);
static void kvx_free_msr_bitmap(struct vcpu *vcpu);
static void kvx_free_vmcs_region(struct vcpu *vcpu);
static void kvx_free_all_msr_areas(struct vcpu *vcpu);
static void free_vmxon_region(struct host_cpu *hcpu);

static struct msr_entry *alloc_msr_entry(size_t n_entries);
static void free_msr_area(struct msr_entry *area, size_t n_entries);
static void populate_msr_load_area(struct msr_entry *area, size_t count,
                                   const uint32_t *indices, const uint32_t *values);
static void populate_msr_store_area(struct msr_entry *area, size_t count, 
                                    const uint32_t *indices);

static inline bool kvx_vcpu_io_bitmap_enabled(struct vcpu *vcpu);
static inline bool kvx_vcpu_msr_bitmap_enabled(struct vcpu *vcpu);
static inline unsigned int msr_area_order(size_t bytes);


/*pin vcpu thread to a specific physical host cpu for cpu affinity*/ 
int kvx_vcpu_pin_to_cpu(struct vcpu *vcpu, int target_cpu_id)
{
    int ret; 

    if(!vcpu->host_task)
    {
        pr_err("KVX: VCPU %d has no host task assigned.\n", vcpu->vcpu_id); 
        return -EINVAL; 
    }

    cpumask_t new_mask; 

    if(!cpu_possible(target_cpu_id))
    {
        pr_err("KVX: Invalid host CPU ID %d for pinning VCPU %d.\n", 
               target_cpu_id, vcpu->vcpu_id); 
        return -EINVAL; 
    }

    cpumask_clear(&new_mask); 
    cpumask_set_cpu(target_cpu_id, &new_mask); 

    ret = set_cpus_allowed_ptr(vcpu->host_task, &new_mask); 
    if(ret == 0)
    {
        PDEBUG("KVX: Successfuly pinned VCPU %d to Host CPU %d.\n", 
               vcpu->vcpu_id, target_cpu_id); 

        vcpu->host_cpu_id = target_cpu_id;
    }
    else{
        pr_err("KVX: Failed to pin VCPU %d to CPU %d, error : %d\n", 
               vcpu->vcpu_id, target_cpu_id, ret); 
    }

    return ret; 
}

/*IO bitmap bit in the execution controls need to be set in order to use io bimaps*/ 
static inline bool kvx_vcpu_io_bitmap_enabled(struct vcpu *vcpu)
{
    return vcpu->controls.primary_proc & VMCS_PROC_USE_IO_BITMAPS; 
}

/*MSR bitmap bit in the execution controls need to be set in order to use msr bimaps */ 
static inline bool kvx_vcpu_msr_bitmap_enabled(struct vcpu *vcpu)
{
    return vcpu->controls.primary_proc & VMCS_PROC_USE_MSR_BITMAPS; 
}

void kvx_vcpu_unpin_and_stop(struct vcpu *vcpu)
{
    set_cpus_allowed_ptr(vcpu->host_task, cpu_online_mask); 

    kthread_stop(vcpu->host_task); 
}

struct host_cpu * host_cpu_create(int logical_cpu_id, int max_vcpus)
{
    struct host_cpu * hcpu; 
    size_t vcpu_array_size; 

    hcpu = kmalloc(sizeof(*hcpu), GFP_KERNEL); 
    if(!hcpu)
        return NULL; 

    hcpu->logical_cpu_id = logical_cpu_id; 

    if(kvx_setup_vmxon_region(hcpu) != 0)
    {
        pr_err("failed to setup vmxon region on host cpu : %d\n", 
               hcpu->logical_cpu_id); 

        hcpu->logical_cpu_id = -1; 
        kfree(hcpu); 
        return NULL; 
    }

    return hcpu; 
}

int kvx_setup_vmxon_region(struct host_cpu *hcpu)
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

int kvx_setup_vmcs_region(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    uint32_t vmcs_size = _get_vmcs_size(); 
    size_t alloc_size = (vmcs_size <= PAGE_SIZE) ? PAGE_SIZE : PAGE_ALIGN(vmcs_size); 

    vcpu->vmcs = (struct vmcs *)__get_free_pages(
        GFP_KERNEL | __GFP_ZERO, get_order(alloc_size)); 
    if(!vcpu->vmcs)
        return -ENOMEM; 

    *(uint32_t *)vcpu->vmcs = _vmcs_revision_id();
    vcpu->vmcs_pa = virt_to_phys(vcpu->vmcs); 

    if(_vmptrld(vcpu->vmcs_pa) != 0)
    {
        pr_err("VMCS load (_vmptrld) failed\n"); 
        return -EFAULT; 
    }

    pr_info("VMCS region alllocated, revision ID set, and loaded\n"); 
    return 0;

}

static void kvx_setup_cr_controls(struct vcpu *vcpu)
{
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
}

/*which IO operation */ 
int kvx_setup_io_bitmap(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL;

    size_t total_bitmap_size = 2 * VMCS_IO_BITMAP_SIZE;
    vcpu->io_bitmap = (uint32_t *)__get_free_pages(GFP_KERNEL, get_order(total_bitmap_size));
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
        kvx_free_io_bitmap(vcpu->io_bitmap); 
        return -EIO; 
    }

    if(_vmwrite(VMCS_IO_BITMAP_B, vcpu->io_bitmap_pa + VMCS_IO_BITMAP_SIZE) != 0)
    {
        PDEBUG("VMWrite VMCS_IO_BITMAP_B failed\n"); 
        kvx_free_io_bitmap(vcpu->io_bitmap); 
        return -EIO; 
    }

    PDEBUG("IO bitmap A physical address : 0x%llx\nIO bitmap B physical address : 0x%llx\n", 
           vcpu->io_bitmap_pa, 
           vcpu->io_bitmap_pa + VMCS_IO_BITMAP_SIZE); 

    return 0; 

}

/*MSRs that cause VM exit when accessed by guest */ 
int kvx_setup_msr_bitmap(struct vcpu *vcpu)
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
        kvx_free_msr_bitmap(vcpu); 
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
        return NULL; 

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
                              const uint32_t *indices, const uint32_t *values)
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
int kvx_setup_msr_areas(struct vcpu *vcpu,
                    const uint32_t *vmexit_list,  size_t vmexit_count,
                    const uint32_t *vmentry_list, const uint32_t *vmentry_values,
                    size_t vmentry_count)
{
    int rc = 0;
    size_t i;

    if (!vcpu)
        return -EINVAL;

        /* VMCS count fields are 16-bit */
    if (vmexit_count > UINT16_MAX || vmentry_count > UINT16_MAX)
        return -EINVAL; 

    /*VM-exit MSR-store area (guest MSRs → memory on exit) */
    vcpu->vmexit_store_area = alloc_msr_entry(vmexit_count);
    if (!vcpu->vmexit_store_area) {
        rc = -ENOMEM;
        goto out;
    }
    vcpu->vmexit_store_pa = page_to_phys(virt_to_page(vcpu->vmexit_store_area));

    /* VM-exit MSR-load area (memory → host MSRs on exit) */
    vcpu->vmexit_load_area = alloc_msr_entry(vmentry_count);
    if (!vcpu->vmexit_load_area)
    {
        rc = -ENOMEM;
        goto out_free_exit_store;
    }
    vcpu->vmexit_load_pa = page_to_phys(virt_to_page(vcpu->vmexit_load_area));

    /* VM-entry MSR-load area (memory → guest MSRs on entry) */
    vcpu->vmentry_load_area = alloc_msr_entry(vmentry_count);
    if (!vcpu->vmentry_load_area) 
    {
        rc = -ENOMEM;
        goto out_free_exit_load;
    }
    vcpu->vmentry_load_pa = page_to_phys(virt_to_page(vcpu->vmentry_load_area));

    populate_msr_store_area(vcpu->vmexit_store_area, vmexit_count, vmexit_list);

    /* On VM-exit, restore host MSR values (typically the ones the guest sees on entry) */
    for (i = 0; i < vmentry_count; ++i) 
    {
        uint32_t idx = vmentry_list[i];
        uint64_t val = 0;

            /* Some MSRs may not be readable; policy decision required */
            val = vmentry_values ? vmentry_values[i] : 0;
        }

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

    if (_vmwrite(VMX_EXIT_MSR_STORE_ADDR, vcpu->vmexit_store_pa) ||
        _vmwrite(VMX_EXIT_MSR_STORE_COUNT, (uint64_t)vmexit_count) ||
        _vmwrite(VMX_EXIT_MSR_LOAD_ADDR,   vcpu->vmexit_load_pa) ||
        _vmwrite(VMX_EXIT_MSR_LOAD_COUNT,  (uint64_t)vmentry_count) ||
        _vmwrite(VMX_ENTRY_MSR_LOAD_ADDR,  vcpu->vmentry_load_pa) ||
        _vmwrite(VMX_ENTRY_MSR_LOAD_COUNT, (uint64_t)vmentry_count)) 
    {
        rc = -EIO;
        goto out_free_all;
    }

    return 0;

out_free_all:
    free_msr_area(vcpu->vmentry_load_area, vmentry_count);
    vcpu->vmentry_load_area = NULL;
    vcpu->vmentry_load_pa = 0;

out_free_exit_load:
    free_msr_area(vcpu->vmexit_load_area, vmentry_count);
    vcpu->vmexit_load_area = NULL;
    vcpu->vmexit_load_pa = 0;

out_free_exit_store:
    free_msr_area(vcpu->vmexit_store_area, vmexit_count);
    vcpu->vmexit_store_area = NULL;
    vcpu->vmexit_store_pa = 0;

out:
    return rc;
}

void kvx_free_all_msr_areas(struct vcpu *vcpu)
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

static int kvx_vcpu_setup_msr_state(struct vcpu *vcpu)
{
    uint64_t vmentry_values[KVX_MAX_MANAGED_MSRS] = {0};
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
    vcpu->efer = EFER_MLE | EFER_LMA | EFER_SCE;

    vmentry_values[0] = vcpu->efer;          // Guest EFER
    vmentry_values[1] = 0;                  // Guest STAR
    vmentry_values[2] = 0;                  // Guest LSTAR
    vmentry_values[3] = 0;                  // Guest CSTAR
    vmentry_values[4] = 0;                  // Guest FMASK
    vmentry_values[5] = vcpu->regs.fs;      // Guest FS_BASE
    vmentry_values[6] = vcpu->regs.gs;      // Guest GS_BASE
    

    return kvx_setup_msr_areas(vcpu, 
                               vcpu->msr_indices, vcpu->msr_count,
                               vcpu->msr_indices, vmentry_values, 
                               vcpu->msr_count); 
}

static void vmx_init_exec_controls(struct vcpu *vcpu)
{
    struct vmx_exec_ctrls *controls = &vcpu->controls; 

    controls->pinbased = 
        VMCS_PIN_EXTINT_EXITING | 
        VMCS_PIN_NMI_EXITING  | 
        VMCS_PIN_VIRTUAL_NMIS |
        VMCS_PIN_PREEMPT_TIMER | 
        VMCS_PIN_POSTED_INTRS; 
    
    controls->primary_proc = 
        VMCS_PROC_USE_IO_BITMAPS | 
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
        VMCS_PROC2_VPID | 
        VMCS_PROC2_UNRESTRICTED_GUEST |
        VMCS_PROC2_ENABLE_VMFUNC; 

    controls->vm_entry = 
        VMCS_ENTRY_LOAD_GUEST_PAT | 
        VMCS_ENTRY_LOAD_IA32_EFER | 
        VMCS_ENTRY_LOAD_DEBUG; 

    controls->vm_exit = 
        VMCS_EXIT_SAVE_IA32_PAT |
        VMCS_EXIT_LOAD_IA32_PAT |
        VMCS_EXIT_SAVE_EFER |
        VMCS_EXIT_LOAD_EFER | 
        VMCS_EXIT_ACK_INTR_ON_EXIT; 
}

static int vmx_apply_exec_controls(struct vcpu *vcpu)
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
    final = (controls->pinbased | allowed1) & (allowed0 | allowed1); 
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

int kvx_setup_exec_controls(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    vmx_init_exec_controls(vcpu); 
    if(vmx_apply_exec_controls(vcpu) != 0)
        return -1; 

    return 0; 

}

struct vcpu *kvx_vcpu_alloc_init(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu;
    int ret; 

    /* Allocate zeroed VCPU struct */
    vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL);
    if (!vcpu)
        return NULL;

    vcpu->vm = vm;
    vcpu->vcpu_id = vcpu_id;

    /* Initialize spinlock */
    spin_lock_init(&vcpu->lock);

    /* Allocate and setup VMCS region */

    if (kvx_setup_vmcs_region(vcpu) != 0) {
        pr_err("Failed to setup VMCS region\n");
        kfree(vcpu);
        vcpu = NULL; 
        return NULL;
    }

    if(kvx_setup_exec_controls(vcpu) != 0)
    {
        pr_err("Failed to setup VMX execution controls\n"); 
I\        kvx_free_all_msr_areas(vcpu); 
        kvx_free_msr_bitmap(vcpu); 
        kvx_free_io_bitmap(vcpu); 
        kvx_free_vmcs_region(vcpu); 
        kfree(vcpu); 
        vcpu = NULL; 
        return NULL; 
    }


     /* Setup IO bitmap */
    if(kvx_vcpu_io_bitmap_enabled(vcpu))
    {
        if (kvx_setup_io_bitmap(vcpu) != 0)
        {
            pr_err("Failed to setup I/O bitmap\n");
            kvx_free_vmcs_region(vcpu); 
            kfree(vcpu);
            vcpu = NULL;
            return NULL;
        }
    }
    
    /* Setup MSR bitmap */
    if(kvx_vcpu_msr_bitmap_enabled(vcpu))
    {
        if (kvx_setup_msr_bitmap(vcpu) != 0) 
        {
            pr_err("Failed to setup MSR bitmap\n");
            kvx_free_io_bitmap(vcpu); 
            kvx_free_vmcs_region(vcpu); 
            kfree(vcpu);
            vcpu = NULL; 
            return NULL; 
        }
    }

    if(kvx_vcpu_setup_msr_state(vcpu) != 0)
    {
        pr_err("Failed to setup MSR areas\n"); 
        kvx_free_msr_bitmap(vcpu); 
        kvx_free_io_bitmap(vcpu); 
        kvx_free_vmcs_region(vcpu); 
        kfree(vcpu); 
        vcpu = NULL; 
        return NULL; 
    }

    pr_info("VCPU %d Initialized successfuly\n", vcpu_id); 

    return vcpu; 

}

void kvx_free_io_bitmap(struct vcpu *vcpu)
{
    if (vcpu->io_bitmap) 
    {
        free_pages((unsigned long)vcpu->io_bitmap, VMCS_IO_BITMAP_PAGES_ORDER);
        vcpu->io_bitmap = NULL;
        vcpu->io_bitmap_pa = 0;
    }
}

void kvx_free_msr_bitmap(struct vcpu *vcpu)
{
    if (vcpu->msr_bitmap) 
    {
        free_page((unsigned long)vcpu->msr_bitmap);
        vcpu->msr_bitmap = NULL;
        vcpu->msr_bitmap_pa = 0;
    }
}

void kvx_free_vmcs_region(struct vcpu *vcpu)
{
    if (vcpu->vmcs) 
    {
        free_pages((unsigned long)vcpu->vmcs, get_order(_get_vmcs_size()));
        vcpu->vmcs = NULL;
        vcpu->vmcs_pa = 0;
    }
}

void free_vmxon_region(struct host_cpu *hcpu)
{
    if (vcpu->vmxon) 
    {
        free_pages((unsigned long)vcpu->vmxon, 0); // VMXON is 1 page
        vcpu->vmxon = NULL;
        vcpu->vmxon_pa = 0;
    }
}

/* Free the entire VCPU */
void free_vcpu(struct vcpu *vcpu)
{
    if (!vcpu)
        return;

    kvx_free_io_bitmap(vcpu);
    kvx_free_msr_bitmap(vcpu);
    kvx_free_vmcs_region(vcpu);

    kfree(vcpu);
}
