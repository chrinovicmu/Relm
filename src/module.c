#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>

#include <include/vmx.h>
#include <include/vm.h>
#include <include/ept.h>
#include <include/vmx_ops.h>
#include <include/vmexit.h>
#include <include/vmcs_state.h>
#include <utils/utils.h>

static struct relm_vm *my_vm = NULL; 

static int __init relm_module_init(void)
{
    int ret;
    int vm_id = 1; 
    int vpid = 1; 

    if(!relm_vmx_support())
    {
        pr_err("RELM: VMX is not surppoted on hardware"); 
        return -1; 
    }
    pr_info("RELM: VMX is surppoted\n"); 

    relm_enable_vmx_operation();

    if(!relm_setup_feature_control())
    {
        pr_err("RELM: failed to setup feature control MSR\n"); 
        return -1; 
    }
    pr_info("RELM: feature control is set\n"); 

    my_vm = relm_create_vm(vm_id, "Test-VM-01", (uint64_t)RELM_VM_GUEST_RAM_SIZE); 
    if(!my_vm)
    {
        pr_err("RELM: VM creation failed - out of memory or EPT srtup failed\n"); 
        return -ENOMEM; 
    }

    pr_info("VM created!!!\n");

    ret = relm_vm_add_vcpu(my_vm, vpid);
    if (ret != 0) 
    {
        pr_err("RELM: Failed to add VCPU with VPID %d (error: %d)\n", 
               vpid, ret);
        return -1; 
 //       goto _cleanup_vm;
    }
    
    pr_info("RELM: VCPU %d added successfully, starting VM...\n", vpid);
    /*

    ret = relm_run_vm(my_vm);
    if (ret != 0)
    {
        pr_err("RELM: Failed to run VM (error: %d)\n", ret);
        goto _cleanup_vm;
    }
    
    pr_info("RELM: VM is now running!\n");
    pr_info("RELM: Module initialization complete\n");
  */   
    return 0;
/*
_cleanup_vm:
    pr_err("RELM: Cleaning up VM due to initialization failure\n");
    relm_destroy_vm(my_vm);
    my_vm = NULL;
    return ret;

    
    return 0;  
    */ 
}

static void __exit relm_module_exit(void)
{
    /*
    pr_info("RELM: Shutting down hypervisor...\n");

    if(my_vm)
    {
        pr_info("RELM: Stopping VM...\n");
        relm_stop_vm(my_vm);
        
        if(my_vm->ops && my_vm->ops->print_stats)
            my_vm->ops->print_stats(my_vm); 

        pr_info("RELM: Destroying VM...\n");
        relm_destroy_vm(my_vm); 
        my_vm = NULL; 
    }
    else{
        pr_info("RELM: No VM to clean\n"); 
    }
    */ 

    pr_info("RELM: Module unloaded succesffully\n"); 
}

module_init(relm_module_init); 
module_exit(relm_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chrinovic M");
MODULE_DESCRIPTION("A Type-1 Linux Hypervisor");
MODULE_VERSION("0.1");
