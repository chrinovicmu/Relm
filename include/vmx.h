#ifndef VMX_H
#define VMX_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <vmx_ops.h>
#include <vmcs.h>
#include <ept.h> 

#define VPID_TO_INDEX(vpid) ((vpid) -1)
#define INDEX_TO_VPID(index) ((index) + 1)
#define VPID_IS_VALID(vpid, max) \
    ((vpid) > 0 && (vpid) <= (max))

#define RELM_MAX_MANAGED_MSRS 8 


struct relm_vm;  // forward declaration

struct vcpu_stats
{
    uint64_t total_exits; 
    uint64_t hypercalls; 
    uint64_t hlt_exits;
    uint64_t cpuid_exits;
    uint64_t start_time_ns; 
    uint64_t end_time_ns; 

}; 
/* Guest registers */
struct guest_regs {

    unsigned long rax;
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;    
    unsigned long rdi;    
    unsigned long rbp;    
    unsigned long rsp;
    
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;

    unsigned long rip;
    unsigned long rflags;

    unsigned long cs, ds, es, fs, gs, ss;

    unsigned long fs_base;
    unsigned long gs_base;
} __attribute__((packed));

enum vcpu_state {
    VCPU_STATE_UNINITIALIZED, 
    VCPU_STATE_INITIALIZED, 
    VCPU_STATE_RUNNING, 
    VCPU_STATE_HALTED, 
    VCPU_STATE_STOPPED, 
    VCPU_STATE_SHUTDOWN, 
    VCPU_STATE_ERROR
}; 

/* Virtual CPU structure */
struct vcpu {

    struct relm_vm *vm;
    struct host_cpu *hcpu;

    uint16_t vpid;
    int target_cpu_id;  

    int launched; 
    enum vcpu_state state; 
    bool halted;

    spinlock_t lock; 
    wait_queue_head_t wq; 

    struct task_struct *host_task; 

    uint8_t host_stack; 
    uint64_t host_rsp; 

    struct vmcs_region *vmcs;
    uint64_t vmcs_pa;

    struct vmx_exec_ctrls controls; 

    void *msr_bitmap;
    uint64_t msr_bitmap_pa; 

    uint8_t *io_bitmap;
    uint64_t io_bitmap_pa;

    uint32_t exception_bitmap; 

    /*MSR managment */ 
    struct msr_entry *vmexit_store_area; 
    uint64_t vmexit_store_pa;

    struct msr_entry *vmexit_load_area; 
    uint64_t vmexit_load_pa; 

    struct msr_entry *vmentry_load_area; 
    uint64_t vmentry_load_pa;

    uint32_t msr_indices[RELM_MAX_MANAGED_MSRS]; 
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

    struct vcpu_stats stats; 

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

struct vcpu *relm_vcpu_alloc_init(struct relm_vm *vm, int vcpu_id);
int relm_vcpu_pin_to_cpu(struct vcpu *vcpu, int target_cpu_id);
void relm_vcpu_unpin_and_stop(struct vcpu *vcpu);
void relm_free_vcpu(struct vcpu *vcpu);
int relm_init_vmcs_state(struct vcpu *vcpu);
void relm_dump_vcpu(struct vcpu *vcpu); 
#endif /* VMX_H */
