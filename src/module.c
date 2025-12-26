#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <stdint.h>
#include "include/hw.h"
#include "include/kvx_vm.h"

static struct kvx_vm *my_vm = NULL; 

static __init kvx_module_init(void)
{
    int ret;
    int vm_id = 1; 
    int vcpu_id = 0; 
   
    hcpu = host_cpu_create(1,1);


    my_vm = kvx_create_vm(vm_id, "Test-VM-01", (uint64_t)KVX_VM_RAM_SIZE); 
    if(!my_vm)
    {
        pr_err("KVX: VM creation failed\n"); 
        return -ENOMEM; 
    }

    ret = kvx_vm_add_vcpu(my_vm, vm_id); 
    if(ret != 0)
    {
        pr_err("KVX: failed to add VCPU 0\n"); 
        goto _cleanup_vm; 
    }

    ret = kvx_run_vm(my_vm, vm_id); 
    if(ret != 0)
    {
        pr_err("KVX: Failed to run VM\n"); 
        goto _cleanup_vm; 
    }

    return 0; 
_cleanup_vm:
    kvx_free_host_cpu(hcpu); 
    kvx_destroy_vm(my_vm); 
    return ret; 
}

static void __exit kvx_module_exit(void)
{
    pr_info("KVX: Shutting down hypervisor...\n"); 
    if(my_vm)
    {
        if(my_vm->ops && my_vm->ops->print_stats)
            my_vm->ops->print_stats(my_vm); 

        kvx_free_host_cpu(hcpu);
        kvx_destroy_vm(my_vm); 
        my_vm = NULL; 
    }

    pr_info("KVX: module unloaded succesffully\n"); 
}

module_init(kvx_module_init); 
module_exit(kvx_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chrinovic M");
MODULE_DESCRIPTION("A Type-1 Hypervisor Kernel Module");
MODULE_VERSION("0.1");
