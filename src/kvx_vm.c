#include <cerrno>
#include <cstddef>
#include <linux/kthread.h> 
#include <sched.h>
#include <linux/smp.h> 
#include "include/hw.h"
#include "include/kvx_vm.h"
/**
 * kvx_vm_add_vcpu - Creates and pins a VCPU to a specific host CPU.
 * @vm: The parent virtual machine struct.
 * @vcpu_id: The index of the VCPU (0 to vm->max_vcpus - 1).
 * @target_host_cpu: The logical ID of the host CPU to pin to.
 * * Returns 0 on success, < 0 on failure.
 */
int kvx_vm_add_vcpu(struct kvx_vm *vm, int vcpu_id, struct host_cpu)
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
    vcpu->target_cpu_id = target_host_cpu; 

    vcpu->host_task = kthread_run(foo, vcpu, "kvx_vm%d_vcpu%d", vm->vm_id, vcpu_id);

    if(IS_ERR(vcpu->host_task))
    {
        pr_err("KVX: Failed to create vcpu thread for VM %d\n", vm->vm_id); 
        ret = PTR_ERR(vcpu->host_task); 
        vm->vcpus[vcpu_id] = NULL; 
        goto _free_vcpu; 
    }

    ret = kvx_vcpu_pin_to_cpu(vcpu, target_host_cpu); 
    if(ret < 0)
    {
        pr_err("KVX: Pinning VCPU %d TO CPU %d failed", vcpu_id, target_host_cpu); 
        kthread_stop(vcpu->host_task);
        vm->vcpus[vcpu_id] = NULL; 
        goto _free_vcpu; 
    }

    vm->online_vpcus++; 
    PDEBUG("KVX: VCPU %d for VM %d successfully pinned to Host CPU %d", 
           vcpu_id, vm->vm_id, target_host_cpu); 

    kvx_vcpu
}
