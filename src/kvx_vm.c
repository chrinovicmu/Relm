#include <cerrno>
#include <cstddef>
#include <linux/kthread.h> 
#include <sched.h>
#include <linux/smp.h> 
#include "include/hw.h"
#include "include/kvx_vm.h"


struct kvx_vm * kvx_create_vm(int vm_id, const char *name, 
                              u64 ram_size, int max_vcpus)
{
    struct kvx_vm *vm;

    vm = kzalloc(sizeof(kvx_vm), GFP_KERNEL); 
    if(!vm)
        return -ENOMEM; 

    spin_lock_init(vm->lock); 

    vcpus = kzalloc((sizeof(struct vcpu*) max_vcpus*), GFP_KERNEL); 
    if(vcpus!)
        return -ENOMEM;

    vm->state = VM_CREATED;
    vm->max_vcpus = max_vcpus; 
    vm->online_vpcus = 0;
    vm->guest_stack = (void*)__get_free_pages(
        GFP_KERNEL | __GFP_ZERO, 
        GUEST_STACK_ORDER,
    ) ; 
    vm->guest_rsp = 
        (unsigned long)vm->guest_stack + (PAGE_SIZE << GUEST_STACK_ORDER); 

}
/**
 * kvx_vm_add_vcpu - Creates and pins a VCPU to a specific host CPU.
 * @vm: The parent virtual machine struct.
 * @vcpu_id: The index of the VCPU (0 to vm->max_vcpus - 1).
 * @target_host_cpu: The logical ID of the host CPU to pin to.
 * * Returns 0 on success, < 0 on failure.
 */
int kvx_vm_add_vcpu(struct kvx_vm *vm, int vcpu_id, struct host_cpu *hcpu)
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
    vcpu->target_cpu_id = hcpu->logical_cpu_id; 

    vcpu->regs.rsp = vm->guest_rsp; 

    vcpu->state = VCPU_STATE_INITIALIZED; 
    vm->online_vpcus++; 

    PDEBUG("KVX: VCPU %d for VM %d successfully pinned to Host CPU %d", 
           vcpu_id, vm->vm_id, target_host_cpu);

_unlock_vm: 
    spin_unlock(&vm->lock); 
    return ret; 
}

int kvx_run_vm(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu; 

    if(vcpu_id >= vm->max_vcpus || vm->vcpus[vcpu_id] == NULL)
        return -EINVAL; 

    vcpu = vm->vcpus[vcpu_id]; 
    vcpu->launched = 1; 

    /*spawn kthread to run the exexution loop */ 
    vcpu->host_task = kthread(kvx_vcpu_loop, vcpu, "kvx_vm%d_vcpu%d", vm->vm_id, vcpu_id); 
    if(IS_ERR(vcpu->host_task))
    {
        pr_err("KVX: Failed to spawn kthread for VCPU %d\n", vcpu_id);
        return PTR_ERR(vcpu->host_task); 
    }

    return 0;
}

int kvx_vcpu_loop(void *data)
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
        kvx_vmentry(vcpu); 


    }
}

void kvx_vmentry(struct vcpu *vcpu)
{
    int launched = vcpu->launched; 
    extern void kvx_vmentry_asm(struct guest_regs, launched); 
    kvx_vmentry_asm(vcpu->regs, launched); 
}

