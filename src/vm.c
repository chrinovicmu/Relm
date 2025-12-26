#include <linux/kthread.h> 
#include <sched.h>
#include <linux/smp.h> 
#include "include/vmx.h"
#include "include/vm.h"

extern void kvx_vmentry_asm(struct guest_regs, int launched); 

static u64 kvx_op_get_uptime(struct kvx_vm *vm)
{
    if (!vm) return 0;
    return ktime_to_ns(ktime_get()) - vm->stats.start_time_ns;
}

static void kvx_op_print_stats(struct kvx_vm *vm)
{
    pr_info("KVX [%s] Stats: Exits=%llu, CPUID=%llu, HLT=%llu\n",
            vm->name, vm->stats.total_exits, 
            vm->stats.cpuid_exits, vm->stats.hlt_exits);
}

static void kvx_op_dump_regs(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu = vm->vcpus[vcpu_id];
    if (!vcpu) return;
    
    pr_info("KVX [%s] VCPU %d RIP: 0x%llx RSP: 0x%llx\n",
            vm->name, vcpu_id, vcpu->regs.rip, vcpu->regs.rsp);
}

static const struct kvx_vm_operations kvx_default_ops = {
    .get_uptime  = kvx_op_get_uptime,
    .print_stats = kvx_op_print_stats,
    .dump_regs   = kvx_op_dump_regs,
};


struct kvx_vm * kvx_create_vm(int vm_id, const char *vm_name, 
                              uint64_t ram_size)
{
    struct kvx_vm *vm;
    struct vcpu *vcpu; 

    vm = kzalloc(sizeof(kvx_vm), GFP_KERNEL); 
    if(!vm)
    {
        pr_err("KVX: Failed to allocate VM header\n"); 
        return NULL; 
    }

    vm->vm_id = vm_id; 
    vm->state = VM_STATE_CREATED; 
    vm->max_vcpus = KVX_MAX_VCPUS; 
    vm->online_vpcus = 0; 
    vm->ops = &kvx_default_ops; 

    if(vm_name)
        strscpy(vm->vm_name, vm_name, sizeof(vm->vm_name)); 

    spin_lock_init(&vm->lock); 

    vm->guest_ram_size = ram_size; 
    vm->guest_ram_base = vmalloc(vm->guest_ram_size); 

    if(!vm->guest_ram_base)
    {
        pr_err("KVX: Failed to allocate %llu bytes of RAM for the VM %d\n", 
               ram_size, vm_id); 
        kfree(vm); 
        return NULL; 
    }

    unsigned char guest_code[] = {
        0xf4, 
        0xeb, 
        0xfd
    }; 

    memset(vm->guest_ram_base, guest_code, vm->guest_ram_size); 

    vm->vcpus = kcalloc(vm->max_vcpus, sizeof(struct vcpu*), GFP_KERNEL); 
    if(!vm->vcpus)
    {
        vfree(vm->guest_ram_base); 
        kfree(vm); 
        return NULL; 
    }

    pr_info("KVX: VM '%s' (ID: %d) created with %llu MB RAM\n", 
            vm->vm_name, vm->vm_id, (ram_size >> 20)); 

    return vm; 
}

void kvx_destroy_vm(struct kvx_vm *vm)
{
    int i; 

    if(!vm)
        return; 

    pr_info("KVX: Destroying VM '%s' (ID: %d)\n", vm->vm_name, vm->vm_id); 

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

                kvx_free_vcpu(vm->vcpus[i]);
                vm->vcpus[i] = NULL; 
            }
        }
        kfree(vm->vcpus); 
    }

    if(vm->guest_ram_base)
    {
        vfree(vm->guest_ram_base);
        vm->guest_ram_base = NULL;
    }

    kfree(vm); 

    pr_info("KVX: VM destruction complete.\n"); 
}

/**
 * kvx_vm_add_vcpu - Creates and pins a VCPU to a specific host CPU.
 * @vm: The parent virtual machine struct.
 * @vcpu_id: The index of the VCPU (0 to vm->max_vcpus - 1).
 * @target_host_cpu: The logical ID of the host CPU to pin to.
 * * Returns 0 on success, < 0 on failure.
 */
int kvx_vm_add_vcpu(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu; 
    int ret = 0; 

    spin_lock(&vm->lock); 

    if(vcpu_id >= vm->max_vcpus || vm->vcpus[vcpu_id] != NULL)
    {
        pr_err("KVX: Invalid or already existing VCPU ID %d.\n", vcpu_id); 
        ret = -EINVAL; 
        goto _unlock_vm; 
    }

    /*allocate and initilize struct vcpu */ 
    vcpu = kvx_vcpu_alloc_init(vm, vcpu_id); 
    if(!vcpu)
    {
        ret = -ENOMEM; 
        goto _unlock_vm; 
    }

    /*store vcpu in the VM 's array */ 
    vm->vcpus[vcpu_id] = vcpu; 

    /*set stack pointer to top of VM RAM */
    vcpu->regs.rsp = vm->guest_ram_size; 

    vcpu->state = VCPU_STATE_INITIALIZED; 
    vm->online_vpcus++; 

    PDEBUG("KVX: VCPU %d for VM %d successfully pinned to Host CPU %d", 
           vcpu_id, vm->vm_id, hcpu->logical_cpu_id);

_unlock_vm: 
    spin_unlock(&vm->lock); 
    return ret; 
}

static int kvx_vcpu_loop(void *data)
{
    struct vcpu *vcpu = (struct vcpu*)data; 

    /*secure context: pin to specific CPU assigned during 'add_cpu' */ 
    kvx_vcpu_pin_to_cpu(vcpu, vcpu->target_cpu_id); 

    /*acitvate hardware: load the vmcs on this specific core */
    if(_vmptrld(vcpu->vmcs_pa))
    {
        pr_err("KVX: VMPTRLD failed on CPU %d\n", vcpu->target_cpu_id); 
        return -1; 
    }

    if(kvx_init_vmcs_state(vcpu))
        return -1; 


    while(!kthread_should_stop())
    {
        kvx_vmentry_asm(vcpu->regs, vcpu->launched); 

        /*if we are here, it means:
        * handler_vmexit() returned 0 (requesred stop)
        * VMLAUNCH/VMRESUME failed (hardware error)
        */ 
        if(vcpu->launched)
        {
            uint64_t error = __vmread(VM_INSTRUCTION_ERROR);
            if(error != 0)
            {
                pr_err("KVX: Hardware Error: %llu\n", error); 
                break; 
            }
        }
        vcpu->launched = 1; 
    }

    __vmclear(vcpu->vmcs_pa); 
    return 0; 
}

int kvx_run_vm(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu; 

    if(vcpu_id >= vm->max_vcpus || vm->vcpus[vcpu_id] == NULL)
        return -EINVAL; 

    vcpu = vm->vcpus[vcpu_id]; 
    vcpu->launched = 1; 

    /*spawn kthread to run the exexution loop */ 
    vcpu->host_task = kthread_run(kvx_vcpu_loop, vcpu, "kvx_vm%d_vcpu%d", vm->vm_id, vcpu_id); 
    if(IS_ERR(vcpu->host_task))
    {
        pr_err("KVX: Failed to spawn kthread for VCPU %d\n", vcpu_id);
        return PTR_ERR(vcpu->host_task); 
    }

    return 0;
}


