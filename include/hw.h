#ifndef HW_H
#define HW_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#include "vmx_ops.h"
#include "vmcs.h"

struct kvx_vm;  // forward declaration

/* Guest registers */
struct guest_regs {
    unsigned long rax, rbx, rcx, rdx;
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
    unsigned long rip, rsp;
    unsigned long rflags;
    unsigned long cs, ds, es, fs, gs, ss;
};

/* Virtual CPU structure */
struct vcpu {

    struct kvx_vm *vm;

    int vcpu_id;
    int host_cpu_id; 

    struct vmcs_region *vmcs;
    u64 vmcs_pa;

    struct vmx_exec_ctrls controls; 

    void *msr_bitmap;
    u64 msr_bitmap_pa; 

    uint8_t *io_bitmap;
    u64 io_bitmap_pa;

    struct msr_entry *vmexit_store_area; 
    u64 vmexit_store_pa;

    struct msr_entry *vmexit_load_area; 
    u64 vmexit_load_pa; 

    struct msr_entry *vmentry_load_area; 
    u64 vmentry_load_pa;

    size_t vmexit_count;
    size_t vmentry_count; 

    struct guest_regs regs;

    unsigned long cr0, cr3, cr4, cr8;
    unsigned long efer;

    u64 exit_reason;
    u64 exit_qualification;

    spinlock_t lock;
};

struct host_cpu
{
    int logical_cpu_id; 
    struct vmxon_region *vmxon; 
    u64 vmxon_pa; 

    int vpcu_count; 
    struct vcpu **vcpus; 

    spinlock_t lock; 
}; 


/* Function declarations */
int vmx_setup_vmxon_region(struct vcpu *vcpu);
int vmx_setup_vmcs_region(struct vcpu *vcpu);
int vmx_setup_io_bitmap(struct vcpu *vcpu); 
int vmx_setup_msr_bitmap(struct vcpu *vcpu); 
int vmx_setup_exec_controls(struct vcpu *vcpu); 

void free_vmxon_region(struct vcpu *vcpu);
void free_vmcs_region(struct vcpu *vcpu); 
void free_io_btimap(struct vcpu *vcpu); 
void free_msr_bitmap(struct vcpu *vcpu); 

struct vcpu *create_vcpu(struct kvx_vm *vm, int vcpu_id);

#endif /* HW_H */
