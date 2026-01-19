#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>        
#include <linux/page-flags.h>
#include <linux/highmem.h>   
#include <vmx.h>
#include <vm.h>
#include <ept.h>
#include <utils.h>

DEFINE_PER_CPU(struct vcpu *, current_vcpu);

static inline void relm_set_current_vcpu(struct vcpu *vcpu)
{
    this_cpu_write(current_vcpu, vcpu);
}

struct vcpu *relm_get_current_vcpu(void)
{
    return this_cpu_read(current_vcpu);
}

/*per-CPU varaible holding the currently executing vcpu.
 * allows handle_vmesit to find VCPU structure wuthout passing
 * it as a parameter*/
extern int relm_vmentry_asm(struct guest_regs *regs, int launched);
extern void relm_vmexit_handler(void);

static const char * const vm_state_names[] = {
    [VM_STATE_CREATED]    = "CREATED",
    [VM_STATE_RUNNING]    = "RUNNING",
    [VM_STATE_SUSPENDED]  = "SUSPENDED",
    [VM_STATE_STOPPED]    = "STOPPED",
}
;
static inline const char *vm_state_to_string(enum vm_state state)
{
    if ((unsigned int)state >= ARRAY_SIZE(vm_state_names))
        return "UNKNOWN";
    return vm_state_names[state] ? vm_state_names[state] : "???";
}

static u64 relm_op_get_uptime(struct relm_vm *vm)
{
    if(!vm)
        return 0; 

    if (!vm) return 0;
    return ktime_to_ns(ktime_get()) - vm->stats.start_time_ns;
}

static void relm_op_print_stats(struct relm_vm *vm)
{
    if(!vm)
        return; 

    pr_info("RELM [%s] Stats: Exits=%llu, CPUID=%llu, HLT=%llu\n",
            vm->vm_name, vm->stats.total_exits,
            vm->stats.cpuid_exits, vm->stats.hlt_exits);
}

static void relm_op_dump_regs(struct relm_vm *vm, int vpid)
{
    if(!vm)
        return; 

    int index = VPID_TO_INDEX(vpid); 
    
    struct vcpu *vcpu = vm->vcpus[index];
    if(!vcpu) 
        return;
   
    pr_info("RELM [%s] VCPU %d RIP: 0x%llx RSP: 0x%llx\n",
            vm->vm_name, vpid, vcpu->regs.rip, vcpu->regs.rsp);
}

static const struct relm_vm_operations relm_default_ops = {
    .get_uptime = relm_op_get_uptime,
    .print_stats = relm_op_print_stats,
    .dump_regs = relm_op_dump_regs,
};

int relm_vm_allocate_guest_ram(struct relm_vm *vm, uint64_t size, uint64_t gpa_start)
{
    struct guest_mem_region *region;
    uint64_t num_pages;
    uint64_t i;
    struct page *page;
    uint64_t gpa;
    uint64_t hpa;
    int ret;

    if(!vm || !vm->ept)
        return -EINVAL;

    /*align size to page boundary */ 
    size = PAGE_ALIGN(size);
    num_pages = size / PAGE_SIZE;

    pr_info("RELM: Allocating %llu pages (%llu MB) of guest RAM at GPA 0x%llx\n",
            num_pages, size / (1024 * 1024), gpa_start);

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if(!region)
        return -ENOMEM;

    region->pages = kzalloc(num_pages * sizeof(struct page*), GFP_KERNEL);
    if(!region->pages)
    {
        kfree(region);
        return -ENOMEM;
    }

    region->gpa_start = gpa_start;
    region->size = size;
    region->num_pages = num_pages;
    region->flags = EPT_RWX;

    for(i = 0; i < num_pages; i++ )
    {
        page = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if(!page)
        {
            pr_err("RELM: Failed to allocate page %llu/%llu\n",
                   i + 1, num_pages);
            ret = -ENOMEM;
            goto _cleanup;
        }

        region->pages[i] = page;
        gpa = gpa_start + (i * PAGE_SIZE);
        hpa = PFN_PHYS(page_to_pfn(page));

        ret = relm_ept_map_page(vm->ept, gpa, hpa, EPT_RWX);
        if(ret < 0)
        {
            pr_err("RELM: Failed to map page at GPA 0x%llx\n", gpa);
            __free_page(page);
            goto _cleanup;
        }
       
        /*progress indicator for every 256MB*/
        if (i > 0 && (i % (256 * 1024 * 1024 / PAGE_SIZE)) == 0)
        {
            pr_info("RELM: Mapped %llu MB...\n",
                    (i * PAGE_SIZE) / (1024 * 1024));
        }
    }

    region->next = vm->mem_regions;
    vm->mem_regions = region;
    vm->total_guest_ram += size;

    pr_info("RELM: Successfully allocated and mapped guest RAM\n");
   
    relm_ept_invalidate_context(vm->ept);
   
    return 0;

_cleanup:
    while (i--) {
        if (region->pages[i])
            __free_page(region->pages[i]);
    }
    kfree(region->pages);
    kfree(region);
    return ret;
}

void relm_vm_free_guest_mem(struct relm_vm *vm)
{
    struct guest_mem_region *region;
    struct guest_mem_region *next;
    uint64_t i;

    if(!vm)
        return;

    region = vm->mem_regions;
    while(region)
    {
        next = region->next;
        if(region->pages)
        {
            for(i = 0; i < region->num_pages; i++)
            {
                if(region->pages[i])
                    __free_page(region->pages[i]);
            }
            kfree(region->pages);
        }
        kfree(region);
        region = next;
    }

    vm->mem_regions = NULL;
    vm->total_guest_ram = 0;
}

struct relm_vm * relm_create_vm(int vm_id, const char *vm_name,
                              uint64_t ram_size)
{
    struct relm_vm *vm;
    int ret = 0;

    vm = kzalloc(sizeof(struct relm_vm), GFP_KERNEL);
    if(!vm)
    {
        pr_err("RELM: Failed to allocate VM header\n");
        return NULL;
    }

    vm->vm_id = vm_id;
    vm->state = VM_STATE_CREATED;
    vm->max_vcpus = RELM_MAX_VCPUS;
    vm->online_vcpus = 0;
    vm->ops = &relm_default_ops;

    if(vm_name)
        strscpy(vm->vm_name, vm_name, sizeof(vm->vm_name));
    else
        snprintf(vm->vm_name, sizeof(vm->vm_name), "vm-%d", vm_id);

    spin_lock_init(&vm->lock);
 
   /*
    if(!relm_ept_check_support())
    {
        pr_err("relm: EPT not supported on this CPU\n");
        goto _out_free_vm;
    }

    vm->ept = relm_ept_context_create();
    if(IS_ERR(vm->ept))
    {
        pr_err("relm: Failed to create EPT context\n");
        vm->ept = NULL;
        goto _out_free_vm;
    }
*/ 
    ret = relm_setup_ept(vm); 
    if(ret < 0)
    {
        pr_err("RELM: Failed to setup EPT context in VM\n"); 
        goto _out_free_vm; 
    }

    pr_info("RELM: Created EPT context for VM %d (EPTP=0x%llx)\n",
            vm_id, vm->ept->eptp);

    if(ram_size > 0)
    {
        ret = relm_vm_allocate_guest_ram(vm, ram_size, 0x0);
        if(ret < 0)
        {
            pr_err("RELM: Failed to allocate guest RAM\n");
            goto _out_free_ept;
        }
        pr_info("RELM: Allocated %llu MB guest RAM\n", ram_size >> 20);
    }

    vm->vcpus = kcalloc(vm->max_vcpus, sizeof(struct vcpu*), GFP_KERNEL);
    if(!vm->vcpus)
    {
        pr_err("RELM: Failed to allocate VCPU array\n");
        goto _out_free_memory;
    }

    vm->state = VM_STATE_INITIALIZED;

    pr_info("RELM: VM '%s' (ID: %d) created with %llu MB RAM\n",
            vm->vm_name, vm->vm_id, (ram_size >> 20));

    return vm;

_out_free_memory:
    relm_vm_free_guest_mem(vm);
_out_free_ept:
    if(vm->ept)
    {
        relm_ept_context_destroy(vm->ept);
        vm->ept = NULL;
    }
_out_free_vm:
    kfree(vm);
    return NULL;
}

void relm_destroy_vm(struct relm_vm *vm)
{
    int i;
    if(!vm)
        return;

    pr_info("RELM: Destroying VM '%s' (ID: %d)\n", vm->vm_name, vm->vm_id);

    /*stop and free all vcpus */
    if(vm->vcpus)
    {
        for(i = 0; i < vm->max_vcpus; i++)
        {
            if(vm->vcpus[i])
            {
                /*if VCPU has runnning thread, stop it first.*/
                if(vm->vcpus[i]->host_task)
                    kthread_stop(vm->vcpus[i]->host_task);
                relm_free_vcpu(vm->vcpus[i]);
                vm->vcpus[i] = NULL;
            }
        }
        kfree(vm->vcpus);
    }

    relm_vm_free_guest_mem(vm);

    if(vm->ept)
    {
        relm_ept_context_destroy(vm->ept);
        vm->ept = NULL;
    }

    kfree(vm);
    pr_info("RELM: VM destruction complete.\n");
}

/*copy data from host kernel memory into guest's physical address space.*/ 
int relm_vm_copy_to_guest(struct relm_vm *vm, uint64_t gpa,
                         const void *data, size_t size)
{
    struct guest_mem_region *region;
    uint64_t region_offset;
    uint64_t page_index;
    uint64_t page_offset;
    uint64_t bytes_to_copy;

    const uint8_t *src = (const uint8_t *)data;
    uint8_t *page_va;
    size_t copied = 0;
    uint64_t current_gpa;
    struct page *page; 

    if(!vm || !data || size == 0)
        pr_err("RELM: Invalid parameters to copy_to_guest\n"); 
        return -EINVAL;
    
    current_gpa = gpa;

    pr_info("RELM: Copying %zu bytes to guest at GPA 0x%llx\n", 
            size, gpa);

    while(copied < size)
    {
        if(!region || current_gpa < region->gpa_start || 
            current_gpa >= (region->gpa_start + region->size))
        {
            region = vm->mem_regions; 
            while(region)
            {
                /*check if current_gpa falls into this region's address space range */ 
                if(current_gpa >= region->gpa_start &&
                    current_gpa < (region->gpa_start + region->size)){
                    break; 
                }
                region = region->next; 
            }
        }

        if(!region)
        {
            pr_err("RELM: GPA %0xllx not mapped in any guest memory region\n", 
                   current_gpa); 
            return copied > 0 ? copied : -EFAULT; 
        }

        /*the offset within the region */ 
        region_offset = current_gpa - region->gpa_start;

        /*page within in region */ 
        page_index = region_offset / PAGE_SIZE; 

        page_offset = region_offset % PAGE_SIZE; 

        /*page boundary 
         * kmap_local_page only maps one 4KB page*/ 
        bytes_to_copy = PAGE_SIZE - page_offset; 

        /*total data boundary
         * ensure we don't copy more that what remains in the source buffer*/ 
        if(bytes_to_copy > (size - copied)){
            bytes_to_copy = size - copied; 
        }

        /*region boundary
         * ensure we don't overflow the guest memory itself*/ 
        if(bytes_to_copy > (region->size - region_offset)){
            bytes_to_copy = region->size - region_offset; 
        }

        /*get physical page corresponding to this guest page*/ 
        page = region->pages[page_index]; 
        if(!page)
        {
            pr_err("RELM: NULL page at index %luu in region at GPA 0x%llx\n", 
                   page_index, region->gpa_start); 
            return copied > 0 ? copied : -EFAULT; 
        }

        /*map guest page into kernel virtual address space */ 
        page_va = kmap_local_page(page); 
        if(!page_va)
        {
            pr_err("RELM: Failed to map guest at GPA 0x%llx\n", 
                   current_gpa); 
        }

        /*perform actaul memory copy*/ 
        memcpy(page_va + page_offset, src + copied, bytes_to_copy); 

        /*host maps guest-backed struct page and writes through 
         * temoparay kernel VA. 
         * these stores populate the CPU's D-cache and are not immediatley
         * visible to guest memory consumers.
         * flush data-cache to ensure DRAM visibility*/ 

        flush_dcache_page(page); 

        kunmap_local(page_va); 

        copied += bytes_to_copy; 
        current_gpa += bytes_to_copy; 

        if (size > (10 * 1024 * 1024) && (copied % (1024 * 1024)) == 0) {
            pr_info("RELM: Copied %zu / %zu bytes...\n", copied, size);
        }     
    }

    pr_info("RELM: Successfully copied %zu bytes to guest memory\n",
            copied);
    return (int)copied; 
}

/*copy data from guest phsyical memory to host */ 
int relm_vm_copy_from_guest(struct relm_vm *vm, const uint64_t gpa,
                            const void *data, size_t size)
{
    struct guest_mem_region *region; 
    uint64_t region_offset; 
    uint64_t page_index; 
    uint64_t page_offset; 
    uint64_t bytes_to_copy; 
    uint8_t *dst = (uint8_t*)data; 
    uint8_t *page_va; 
    size_t copied = 0; 
    uint64_t current_gpa; 
    struct page *page; 

    if(!vm || !data || size == 0)
    {
        pr_err("RELM: Invalid parameters to copy_from_guest\n"); 
        return -EINVAL; 
    }

    current_gpa = gpa; 

    pr_info("RELM: Copying %zu bytes from guest at GPA 0x%llx\n",
            size, gpa);

    while(copied < size)
    {
        if(!region || current_gpa < region->gpa_start || 
            current_gpa >= (region->gpa_start + region->size)){
        
            region = vm->mem_regions; 
            while(region)
            {
            if(current_gpa >= region->gpa_start &&
               current_gpa < (region->gpa_start + region->size)){
                break;
                }
            region = region->next; 
            }
        }

        if(!region)
        {
            pr_err("RELM: GPA 0x%llx not mapped in any guest memory region\n", 
                   current_gpa); 
            return copied > 0 ? copied : -EFAULT; 
        }

        region_offset = current_gpa - region->gpa_start; 
        page_index = region_offset / PAGE_SIZE; 
        page_offset = region_offset % PAGE_SIZE; 

        bytes_to_copy = PAGE_SIZE - page_offset; 
        if(bytes_to_copy > (size - copied)){
            bytes_to_copy = size - copied; 
        }
        if(bytes_to_copy > (region->size - region_offset)){
            bytes_to_copy = region->size - region_offset; 
        }

        page = region->pages[page_index]; 
        if(!page)
        {
            pr_err("RELM: NULL page at index %llu\n", page_index); 
            return copied > 0 ? copied : -EFAULT; 
        }

        page_va = kmap_local_page(page); 
        if(!page_va)
        {
            pr_err("RELM: Failed to map guest paged\n"); 
            return copied > 0 ? copied : -EFAULT; 
        }

        memcpy(dst + copied, page_va + page_offset, bytes_to_copy);

        /*flushing might be unnnecesay here 
        flush_dcache_page(page); 
        */ 

        kunmap_local(page_va); 

        copied += bytes_to_copy; 
        current_gpa += bytes_to_copy; 
    }

    pr_info("RELM: Successfully copied %zu bytes from guest memory\n", 
            copied);

    return (int)copied;

}

/*zero out a range og guest memory */ 
int relm_vm_zero_guest_memory(struct relm_vm *vm, uint64_t gpa, size_t size)
{
    struct guest_mem_region *region;
    uint64_t region_offset;
    uint64_t page_index;
    uint64_t page_offset;
    uint64_t bytes_to_zero;
    uint8_t *page_va;
    size_t zeroed = 0;
    uint64_t current_gpa;
    struct page *page;

    if (!vm || size == 0) {
        return -EINVAL;
    }

    current_gpa = gpa;

    while (zeroed < size) 
    {
        if(!region || current_gpa < region->gpa_start || 
            current_gpa >= (region->gpa_start, region->size))
        {
            region = vm->mem_regions;
            while (region) 
            {
                if (current_gpa >= region->gpa_start &&
                    current_gpa < (region->gpa_start + region->size)) {
                    break;
                }

                region = region->next;
            }
        }

        if (!region) {
            return zeroed > 0 ? zeroed : -EFAULT;
        }

        region_offset = current_gpa - region->gpa_start;
        page_index = region_offset / PAGE_SIZE;
        page_offset = region_offset % PAGE_SIZE;

        bytes_to_zero = PAGE_SIZE - page_offset;
        if (bytes_to_zero > (size - zeroed)) {
            bytes_to_zero = size - zeroed;
        }

        page = region->pages[page_index];
        if (!page) {
            return zeroed > 0 ? zeroed : -EFAULT;
        }

        page_va = kmap_local_page(page);
        if (!page_va) {
            return zeroed > 0 ? zeroed : -ENOMEM;
        }

        memset(page_va + page_offset, 0, bytes_to_zero);

        /*mark page as dirty*/ 
        set_page_dirty(page); 

        flush_dcache_page(page);

        kunmap_local(page_va);

        zeroed += bytes_to_zero;
        current_gpa += bytes_to_zero;
    }

    return (int)zeroed;
}

/**
 * relm_vm_add_vcpu - Creates and pins a VCPU to a specific host CPU.
 * @vm: The parent virtual machine struct.
 * @vcpu_id: The index of the VCPU (0 to vm->max_vcpus - 1).
 * @target_host_cpu: The logical ID of the host CPU to pin to.
 * * Returns 0 on success, < 0 on failure.
 */
int relm_vm_add_vcpu(struct relm_vm *vm, int vpid)
{
    struct vcpu *vcpu;
    int index;
    int ret;

    if(!vm)
    {
        pr_err("RELM: Invalid VM\n");
        return -EINVAL;
    }

    if(!VPID_IS_VALID(vpid, vm->max_vcpus))
    {
        pr_err("RELM: Invalid VPID (must be < max_vcpus)\n");
        return -EINVAL;
    }

    index = VPID_TO_INDEX(vpid);

    if(vm->vcpus[index])
    {
        pr_err("RELM: VCPU with VPID %u already exists\n", vpid);
        return -EEXIST;
    }

    pr_info("relm: Creating VCPU with VPID %u\n", vpid);

    /*allocate and initilize struct vcpu */
    vcpu = relm_vcpu_alloc_init(vm, vpid);
    if(!vcpu)
    {
        pr_err("RELM: Failed to allocate VCPU\n");
        return -ENOMEM;
    }
   
    /*store vcpu in the VM 's array */
    vm->vcpus[index] = vcpu;

    /*set stack pointer to top of VM RAM */
    vcpu->regs.rsp = vm->total_guest_ram;   // Note: might need -8 or alignment
    vcpu->state = VCPU_STATE_INITIALIZED;
    vm->online_vcpus++;

    PDEBUG("RELM: VCPU %d for VM %d successfully pinned to Host CPU %d",
           index, vm->vm_id, vcpu->target_cpu_id);

    return 0;
}

struct vcpu *relm_vm_get_vcpu(struct relm_vm *vm, uint16_t vpid)
{
    struct vcpu *vcpu = NULL;
    int index;

    if(!vm || !vm->vcpus)
        return NULL;

    if(!VPID_IS_VALID(vpid, vm->max_vcpus))
        return NULL;

    index = VPID_TO_INDEX(vpid);

    spin_lock(&vm->lock);
    vcpu = vm->vcpus[index];
    spin_unlock(&vm->lock);

    return vcpu;
}

/*main execution loop of VCPU
 * this functino runs in a kernel thread and repeatedly
 * enters the guest runtil told to stop */
static int relm_vcpu_loop(void *data)
{
    struct vcpu *vcpu = (struct vcpu*)data;
    int ret;
    int vm_entry_status;

    pr_info("RELM: VCPU %d thread starting on CPU %d\n",
            vcpu->vpid, smp_processor_id());

    /*secure context: pin to specific CPU assigned during 'add_cpu' */
    ret = relm_vcpu_pin_to_cpu(vcpu, vcpu->target_cpu_id);
    if(ret < 0)
    {
        pr_err("RELM: Failed to pin VCPU %u to CPU %d\n",
               vcpu->vpid, vcpu->target_cpu_id);
        return ret;
    }

    /*acitvate hardware: load the vmcs on this specific core */
    if(_vmptrld(vcpu->vmcs_pa))
    {
        pr_err("RELM: VMPTRLD failed for VCPU %d on CPU %d\n",
               vcpu->vpid, vcpu->target_cpu_id);
        return -EIO;
    }

    pr_info("RELM: VMCS loaded for VCPU %d (PA=0x%llx)\n",
            vcpu->vpid, vcpu->vmcs_pa);

    ret = relm_init_vmcs_state(vcpu);
    if(ret < 0)
    {
        pr_err("RELM: Failed to initialize VMCS state\n");
        __vmclear(vcpu->vmcs_pa);
        return ret;
    }

    vcpu->state = VCPU_STATE_RUNNING;
    pr_info("RELM: VCPU %d entering execution loop\n", vcpu->vpid);

    while(!kthread_should_stop())
    {
        ret = relm_vmentry_asm(&vcpu->regs, vcpu->launched);

        /*we only reach here if VMLAUNCH/VMRESUME fails */
        pr_err("RELM: [VPID=%u] VM-%s FAILED!\n",
               vcpu->vpid, vcpu->launched ? "RESUME" : "LAUNCH");
       
        uint64_t error = __vmread(VMCS_INSTRUCTION_ERROR_FIELD);
       
        pr_err("RELM: [VPID=%u] VM instruction error: %llu\n",
               vcpu->vpid, error);
       
        pr_err("RELM: [VPID=%u] Guest state at failure:\n", vcpu->vpid);
        pr_err(" RIP: 0x%016llx\n", __vmread(GUEST_RIP));
        pr_err(" RSP: 0x%016llx\n", __vmread(GUEST_RSP));
        pr_err(" RFLAGS: 0x%016llx\n", __vmread(GUEST_RFLAGS));
        pr_err(" CR0: 0x%016llx\n", __vmread(GUEST_CR0));
        pr_err(" CR3: 0x%016llx\n", __vmread(GUEST_CR3));
        pr_err(" CR4: 0x%016llx\n", __vmread(GUEST_CR4));
       
        pr_err("RELM: [VPID=%u] Dumping VMCS for analysis:\n", vcpu->vpid);
        relm_dump_vcpu(vcpu);
       
        break;
    }

    pr_info("RELM: [VPID=%u] Execution loop exiting\n", vcpu->vpid);
    pr_info("RELM: [VPID=%u] Total VM-exits handled: %llu\n",
            vcpu->vpid, vcpu->stats.total_exits);

    if(vcpu->state == VCPU_STATE_RUNNING)
        vcpu->state = VCPU_STATE_STOPPED;

    relm_set_current_vcpu(NULL);
    __vmclear(vcpu->vmcs_pa);

    pr_info("RELM: [VPID=%u] Thread exiting\n", vcpu->vpid);

    return 0;
}

int relm_run_vcpu(struct relm_vm *vm, uint64_t vpid)
{
    struct vcpu *vcpu;
    long err;

    if(!vm)
        return -EINVAL;

    vcpu = relm_vm_get_vcpu(vm, vpid);
    if(!vcpu)
    {
        pr_err("RELM: VCPU VPID=%u, does not exist\n", (uint32_t)vpid);
        return -ENOENT;
    }

    if(vcpu->host_task)
    {
        pr_err("RELM: VCPU VPID=%u already running\n", (uint32_t)vpid);
        return -EBUSY;
    }

    vcpu->launched = 0;
    vcpu->halted = false;
    vcpu->stats.total_exits = 0;
    vcpu->exit_reason = 0;

    pr_info("RELM: Starting VCPU VPID=%u\n", (uint32_t)vpid);

    vcpu->host_task = kthread_create(
        relm_vcpu_loop,
        vcpu,
        "relm_vm%d_vpid%u",
        vm->vm_id,
        (uint32_t)vpid
    );

    if(IS_ERR(vcpu->host_task))
    {
        err = PTR_ERR(vcpu->host_task);
        pr_err("RELM: Failed to create thread for VPID %u: %ld\n",
               (uint32_t)vpid, err);
        vcpu->host_task = NULL;
        return err;
    }

    wake_up_process(vcpu->host_task);
    pr_info("RELM: VCPU VPID=%u thread started\n", (uint32_t)vpid);

    return 0;
}

int relm_stop_vcpu(struct relm_vm *vm, uint16_t vpid)
{
    struct vcpu *vcpu;
    int ret;

    if(!vm)
        return -EINVAL;

    vcpu = relm_vm_get_vcpu(vm, vpid);
    if(!vcpu)
    {
        pr_err("RELM: VCPU VPID=%u does not exist\n", vpid);
        return -ENOENT;
    }

    if(!vcpu->host_task)
    {
        pr_warn("RELM: VCPU VPID=%u is not running\n", vpid);
        return 0;
    }

    pr_info("RELM: Stopping VCPU VPID=%u...............................\n", vpid);
   
    ret = kthread_stop(vcpu->host_task);
   
    vcpu->host_task = NULL;
    vcpu->state = VCPU_STATE_STOPPED;

    pr_info("RELM: VCPU VPID=%u stopped (total exits: %llu)\n",
            vpid, vcpu->stats.total_exits);

    return 0;
}

// Note: This function appears to be legacy/incomplete.
// Consider removing it or reimplementing properly.
int relm_run_vm(struct relm_vm *vm)
{
    int i; 
    int ret = 0; 
    int started_vcpus = 0; 
    struct vcpu *vcpu; 

    if(!vm)
    {
        pr_err("RELM: Cannot run NULL VM\n"); 
        return -EINVAL; 
    }

    if(vm->state != VM_STATE_INITIALIZED && vm->state != VM_STATE_STOPPED) 
    {
        pr_err("RELM: VM '%s' is not in runnable state (current state : %s)\n",
               vm->vm_name, 
               vm_state_to_string(vm->state));
        return -EINVAL; 
    }

    if (vm->online_vcpus == 0) {
        pr_err("RELM: VM '%s' has no VCPUs configured\n", vm->vm_name);
        return -ENOENT;
    }

    pr_info("RELM: Starting VM '%s' (ID: %d) with %d VCPU(s)\n",
            vm->vm_name, vm->vm_id, vm->online_vcpus);


    vm->stats.start_time_ns = ktime_to_ns(ktime_get());

    spin_lock(&vm->lock);
    vm->state = VM_STATE_RUNNING;
    spin_unlock(&vm->lock);


    for(i = 0; i < vm->max_vcpus; i++)
    {
        vcpu = vm->vcpus[i]; 

        if(!vcpu){
            continue;
        }

        if (vcpu->host_task)
        {
            pr_warn("RELM: VCPU VPID=%u already running, skipping\n",
                    vcpu->vpid);
            started_vcpus++;
            continue;
        }

        pr_info("RELM: Launching VCPU VPID=%u (target CPU: %d)\n",
                vcpu->vpid, vcpu->target_cpu_id);

        ret = relm_run_vcpu(vm, vcpu->vpid); 
        if(ret < 0)
        {
            pr_err("RELM: Failed to start VCPU VPID=%u: %d\n", 
                   vcpu->vpid, ret); 

            goto _stop_all_vcpus; 
        }

        started_vcpus++; 
    }

    if (started_vcpus == 0) 
    {
        pr_err("RELM: Failed to start any VCPUs for VM '%s'\n",
               vm->vm_name);
        vm->state = VM_STATE_STOPPED;
        return -EIO;
    }

    pr_info("RELM: VM '%s' successfully started with %d/%d VCPUs running\n",
            vm->vm_name, started_vcpus, vm->online_vcpus);

    return 0;

_stop_all_vcpus:

    pr_err("RELM: Stopping all VCPUs due to launch failure\n");

    for (i = 0; i < vm->max_vcpus; i++) 
    {
        vcpu = vm->vcpus[i];
        if (!vcpu || !vcpu->host_task) {
            continue;
        }

        pr_info("RELM: Stopping VCPU VPID=%u\n", vcpu->vpid);
        relm_stop_vcpu(vm, vcpu->vpid);
    }

    spin_lock(&vm->lock);
    vm->state = VM_STATE_INITIALIZED;
    spin_unlock(&vm->lock);

    return ret;
}

int relm_stop_vm(struct relm_vm *vm)
{
    int i;
    int ret;
    int stopped_vcpus = 0;
    struct vcpu *vcpu;

    if (!vm) 
    {
        pr_err("RELM: Cannot stop NULL VM\n");
        return -EINVAL;
    }

    if (!vm->vcpus)
    {
        pr_warn("RELM: VM '%s' has no VCPU array\n", vm->vm_name);
        return -EINVAL;
    }

    pr_info("RELM: Stopping VM '%s' (ID: %d)\n",
            vm->vm_name, vm->vm_id);

    for (i = 0; i < vm->max_vcpus; i++) {
        vcpu = vm->vcpus[i];

        if (!vcpu) {
            continue;
        }

        if (!vcpu->host_task) {
            continue;
        }

        pr_info("RELM: Stopping VCPU VPID=%u\n", vcpu->vpid);

        ret = relm_stop_vcpu(vm, vcpu->vpid);
        if (ret < 0)
        {
            pr_err("RELM: Failed to stop VCPU VPID=%u: %d\n",
                   vcpu->vpid, ret);
        } else {
            stopped_vcpus++;
        }
    }

    spin_lock(&vm->lock);
    vm->state = VM_STATE_STOPPED;
    spin_unlock(&vm->lock);

    pr_info("RELM: VM '%s' stopped (%d VCPUs stopped)\n",
            vm->vm_name, stopped_vcpus);

    if (vm->ops && vm->ops->print_stats) {
        vm->ops->print_stats(vm);
    }

    return 0;
}
