#include <stdint.h>
#ifnde VM_H
#define VM_H

#define KVX_MAX_VCPUS 1  
#define GUEST_STACK_ORDER 2 

#include "hw.h"

/*represents a single virtual machine */ 

enum vm_state {
    VM_CREATED, 
    VM_RUNNING, 
    VM_SUSPENDED, 
    VM_STOPPED
}; 

struct kvx_vm
{
    int vm_id;
    char name[16]; 

    uint8_t guest_stack; 
    uint64_t guest_rsp;  

    u64 guest_ram_size;
    void *guest_ram_base; 

    int max_vcpus;
    int online_vcpus;
    struct vcpu *vcpus; 

    vm_state state; 

    spinlock_t lock; 
}; 

struct kvx_vm * kvx_create_vm(int vm_id, const char *name, u64 ram_size, int max_vcpus); 
int kvx_vm_add_vcpu(struct kvx_vm *vm, int vcpu_id, struct host_cpu); 
void kvx_vmentry(struct vcpu *vcpu, int launched); 
#endif 
