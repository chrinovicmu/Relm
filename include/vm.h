#ifndef VM_H
#define VM_H


#include <vmx.h>
#include <vmx_ops.h>
#include <ept.h> 

#define RELM_MAX_VCPUS 1  
#define GUEST_STACK_ORDER 2 
#define RELM_VM_GUEST_RAM_SIZE 128 * 1024 * 1024 
    
/*represents a single virtual machine */ 

struct guest_mem_region
{
    uint64_t gpa_start; 
    uint64_t size; 
    struct page **pages; 
    uint64_t num_pages; 
    uint64_t flags;
    struct guest_mem_region *next; 
}; 

enum vm_state {
    VM_STATE_CREATED,
    VM_STATE_INITIALIZED, 
    VM_STATE_RUNNING, 
    VM_STATE_SUSPENDED, 
    VM_STATE_STOPPED
}; 

struct relm_vm_stats
{
    uint64_t total_exits; 
    uint64_t hypercalls; 
    uint64_t hlt_exits;
    uint64_t cpuid_exits;
    uint64_t start_time_ns; 
    uint64_t end_time_ns; 

}; 

struct relm_vm
{
    int vm_id;
    char vm_name[16];

    struct guest_mem_region *mem_regions; 
    struct ept_context *ept; 
    uint64_t total_guest_ram; 

    int max_vcpus;
    int online_vcpus;
    struct vcpu **vcpus; 

    enum vm_state state; 
    struct relm_vm_stats stats; 
    const struct relm_vm_operations *ops; 

    spinlock_t lock; 
}; 

struct relm_vm_operations{
    uint64_t (*get_uptime)(struct relm_vm *vm); 
    uint64_t (*get_cpu_utilization)(struct relm_vm *vm);
    void (*dump_regs)(struct relm_vm *vm, int vcpu_id); 
    void (*print_stats)(struct relm_vm *vm); 
}; 


struct relm_vm * relm_create_vm(int vm_id, const char *name, uint64_t ram_size); 
void relm_destroy_vm(struct relm_vm *vm); 
int relm_vm_add_vcpu(struct relm_vm *vm, int vcpu_id); 
int relm_vm_allocate_guest_ram(struct relm_vm *vm, uint64_t size, uint64_t gpa_start); 
int relm_vm_map_mmio_region(struct relm_vm *vm, uint64_t gpa, uint64_t hpa, uint64_t size); 
void relm_vm_free_guest_memory(struct relm_vm *vm); 
int relm_vm_copy_to_guest(struct relm_vm *vm, uint64_t gpa, const void *data, size_t size);
int relm_vm_copy_from_guest(struct relm_vm *vm, uint64_t gpa, const void *data, size_t size);
int relm_vm_zero_guest_memory(struct relm_vm *vm, uint64_t gpa, size_t size)
int relm_run_vm(struct relm_vm *vm);
int relm_stop_vm(struct relm_vm *vm);

#endif 
