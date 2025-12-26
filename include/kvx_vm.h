#include <stdint.h>
#ifnde VM_H
#define VM_H

#define KVX_MAX_VCPUS 1  
#define GUEST_STACK_ORDER 2 
#define KVX_VM_RAM_SIZE 128 * 1024 * 1024; 

#include "hw.h"

/*represents a single virtual machine */ 

enum vm_state {
    VM_STATE_CREATED, 
    VM_STATE_RUNNING, 
    VM_STATE_SUSPENDED, 
    VM_STATE_STOPPED
}; 

struct kvx_vm_stats
{
    uint64_t total_exits; 
    uint64_t hypercalls; 
    uint64_t hlt_exits;
    uint64_t cpuid_exits;
    uint64_t start_time_ns; 
    uint64_t end_time_ns; 

}
struct kvx_vm
{
    int vm_id;
    char vm_name[16];

    u64 guest_ram_size;
    void *guest_ram_base; 

    int max_vcpus;
    int online_vcpus;
    struct vcpu **vcpus; 

    vm_state state; 
    struct kvx_vm_stats stats; 
    const struct kvx_vm_operations *ops; 

    spinlock_t lock; 
}; 

struct kvx_vm_operations{
    uint64_t (*get_uptime)(struct kvx_vm *vm); 
    uint64_t (*get_cpu_utilization)(struct kvx_vm *vm);
    void (*dump_regs)(struct kvx_vm *vm, int vcpu_id); 
    void (*print_stas)(struct kvx_vm *vm); 
}; 


struct kvx_vm * kvx_create_vm(int vm_id, const char *name, u64 ram_size); 
void kvx_destroy_vm(struct kvx_vm *vm); 
int kvx_vm_add_vcpu(struct kvx_vm *vm, int vcpu_id, struct host_cpu); 
#endif 
