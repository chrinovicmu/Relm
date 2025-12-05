#ifnde VM_H
#define VM_H

/*represents a single virtual machine */ 
struct kvx_vm
{
    int vm_id;
    char name[16]; 

    u64 guest_ram_size;
    void *guest_ram_base; 

    int max_vcpus;
    int online_vcpus;
    struct vcpu **vcpus; 

    spinlock_t lock; 
}

#endif 
