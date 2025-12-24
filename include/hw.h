#ifndef HW_H
#define HW_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#include "vmx_ops.h"
#include "vmcs.h"

#define KVX_MAX_MANAGED_MSRS 8 

struct kvx_vm;  // forward declaration

/* Guest registers */
struct guest_regs {
    unsigned long rax, rbx, rcx, rdx;
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
    unsigned long rip, rsp;
    unsigned long rflags;
    unsigned long cs, ds, es, fs, gs, ss;
};

enum vcpu_state {
    VCPU_STATE_UNINITIALIZED, 
    VCPU_STATE_INITIALIZED, 
    VCPU_STATE_RUNNNING, 
    VCPU_STATE_HALTED, 
    VCPU_STATE_BLOCKED, 
    VCPU_STATE_SHUTDOWN, 
    VCPU_STATE_ERROR
}; 

/* Virtual CPU structure */
struct vcpu {

    struct kvx_vm *vm;
    int vcpu_id;
    int host_cpu_id; 

    int launched; 
    enum vcpu_state state; 
    bool halted;

    spinlock_t lock; 
    wait_queue_head_t wq; 

    struct task_struct *host_struct; 

    uint8_t host_stack; 
    uint64_t host_rsp; 

    struct vmcs_region *vmcs;
    uint64_t vmcs_pa;

    struct vmx_exec_ctrls controls; 

    void *msr_bitmap;
    uint64_t msr_bitmap_pa; 

    uint8_t *io_bitmap;
    uint64_t io_bitmap_pa;

    /*MSR managment */ 
    struct msr_entry *vmexit_store_area; 
    uint64_t vmexit_store_pa;

    struct msr_entry *vmexit_load_area; 
    uint64_t vmexit_load_pa; 

    struct msr_entry *vmentry_load_area; 
    uint64_t vmentry_load_pa;

    uint32_t msr_indices[KVX_MAX_MANAGED_MSRS]; 
    uint32_t msr_count; 

    size_t vmexit_count;
    size_t vmentry_count; 

    struct guest_regs regs;

    unsigned long cr0, cr3, cr4, cr8;
    unsigned long efer;

    uint64_t gdtr_base; 
    u16 gdtr_limit; 

    uint64_t idtr_base; 
    u16 idtr_limit; 

    uint64_t exit_reason;
    uint64_t exit_qualification;

};

struct host_cpu
{
    int logical_cpu_id; 
    struct vmxon_region *vmxon; 
    uint64_t vmxon_pa; 

    int vpcu_count; 
    struct vcpu **vcpus; 

    spinlock_t lock; 
};

struct host_cpu *host_cpu_create(int logical_cpu_id, int max_vcpus);
struct vcpu *kvx_vcpu_alloc_init(struct kvx_vm *vm, int vcpu_id);
int kvx_vcpu_pin_to_cpu(struct vcpu *vcpu, int target_cpu_id);
void kvx_vcpu_unpin_and_stop(struct vcpu *vcpu);
void free_vcpu(struct vcpu *vcpu);
int kvx_init_vmcs_state(struct vcpu *vcpu); 

#endif /* HW_H */
