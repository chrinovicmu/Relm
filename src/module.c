#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <vmx.h>
#include <vm.h>

static struct kvx_vm *my_vm = NULL; 

static int __init kvx_module_init(void)
{
    int ret;
    int vm_id = 1; 
    int vpid = 1; 

    my_vm = kvx_create_vm(vm_id, "Test-VM-01", (uint64_t)KVX_VM_GUEST_RAM_SIZE); 
    if(!my_vm)
    {
        pr_err("KVX: VM creation failed - out of memory or EPT srtup failed\n"); 
        return -ENOMEM; 
    }

    ret = kvx_vm_add_vcpu(my_vm, vpid);
    if (ret != 0) 
    {
        pr_err("KVX: Failed to add VCPU with VPID %d (error: %d)\n", 
               vpid, ret);
        goto _cleanup_vm;
    }
    
    pr_info("KVX: VCPU %d added successfully, starting VM...\n", vpid);

    ret = kvx_run_vm(my_vm);
    if (ret != 0)
    {
        pr_err("KVX: Failed to run VM (error: %d)\n", ret);
        goto _cleanup_vm;
    }
    
    pr_info("KVX: VM is now running!\n");
    pr_info("KVX: Module initialization complete\n");
    
    return 0;

_cleanup_vm:
    pr_err("KVX: Cleaning up VM due to initialization failure\n");
    kvx_destroy_vm(my_vm);
    my_vm = NULL;
    return ret;
}

static void __exit kvx_module_exit(void)
{
    pr_info("KVX: Shutting down hypervisor...\n");

    if(my_vm)
    {
        pr_info("KVX: Stopping VM...\n");
        kvx_stop_vm(my_vm);
        
        if(my_vm->ops && my_vm->ops->print_stats)
            my_vm->ops->print_stats(my_vm); 

        pr_info("KVX: Destroying VM...\n");
        kvx_destroy_vm(my_vm); 
        my_vm = NULL; 
    }
    else{
        pr_info("KVX: No VM to clean\n"); 
    }

    pr_info("KVX: Module unloaded succesffully\n"); 
}

module_init(kvx_module_init); 
module_exit(kvx_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chrinovic M");
MODULE_DESCRIPTION("A Type-1 Hypervisor Kernel Module");
MODULE_VERSION("0.1");
