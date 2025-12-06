#include <stdint.h>
#include <string.h>
#ifnde VM_H
#define VM_H

#include "hw.h"

/*represents a single virtual machine */ 

enum vm_state {
    VM_CREATES, 
    VM_RUNNING, 
    VM_SUSPENDED, 
    VM_STOPPED
}; 

struct kvx_vm
{
    int vm_id;
    char name[16]; 

    u64 guest_ram_size;
    void *guest_ram_base; 

    int max_vcpus;
    int online_vcpus;
    struct vcpu **vcpus; 

    vm_state state; 

    spinlock_t lock; 
}; 

struct kvx_vm * create_vm(int vm_id, const char *name, u64 ram_size, int max_vcpus)
{
    struct kvx_vm *vm;

    vm = kzalloc(sizeof(*vm), GFP_KERNEL);
    if(!vm)
        return NULL; 

    vm->vm_id = vm_id; 
    strncpy(vm->name, name, sizeof(vm->name)- 1); 

    vm->guest_ram_base = kzalloc(ram_size, GFP_KERNEL); 
    if(!vm->guest_ram_base)
    {
        kfree(vm);
        return NULL; 
    }


    vm->vcpus = kzalloc(sizeof(struct vcpu *) *max_vcpus, GFP_KERNEL); 
    if(!vm->vcpus)
    {
        kfree(vm->guest_ram_base);
        kfree(vm);
        return NULL; 
    }

    spin_lock_init(&vm->lock); 

    return vm; 

}

#endif 
