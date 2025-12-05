#ifndef HW_H 
#define HW_H


struct guest_regs
{
    unsigned long rax; 
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx; 

    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11; 
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;

    unsigned long rip;
    unsigned long rsp;

    unsigned long rflags;

    unsigned long cs;
    unsigned long ds;
    unsigned long es;
    unsigned long fs;
    unsigned long gs;
    unsigned long ss;
}; 

struct vpcu
{
    struct vm   *vm;
    int         *vpcu_id;
    
    struct vmcs *vmcs;
    u64         vmcs_pa;
    void        *msr_bitmap; 

    struct guest_regs regs;

    unsigned long cr0, cr3, cr4, cr8;
    unsigned long efer;

    u64 exit_reason; 
    u64 exit_qualification;

    spinlock_t lock; 
}

#endif 
