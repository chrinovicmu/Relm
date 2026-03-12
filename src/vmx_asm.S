
#this file contains the vmx transition code. 
#it is reposible for: 
#   - loading guest gneral purpost registers 
#   - executing VM-entry (VMLAUNCH / VMRESUME)
#   - regainning control on VM-exit 

# This code runs in kernel mode, with interrupts disabled or controlled,
# and must obey the System V AMD64 ABI where applicable.

.globl relm_vmentry_asm 
.globl relm_vmexit_handler 

.extern relm_vmentry_save_rsp
.extern relm_vmentry_get_rsp 
.extern handle_vmexit

# streucture offsets (match struct guest_regs layout)
.set VCPU_R15, 0 
.set VCPU_R14, 8 
.set VCPU_R13, 16 
.set VCPU_R12, 24
.set VCPU_R11, 32
.set VCPU_R10, 40
.set VCPU_R9,  48
.set VCPU_R8,  56
.set VCPU_RBP, 64
.set VCPU_RDI, 72
.set VCPU_RSI, 80
.set VCPU_RDX, 88
.set VCPU_RCX, 96
.set VCPU_RBX, 104
.set VCPU_RAX, 112

.set GREGS_RAX,   0
.set GREGS_RBX,   8
.set GREGS_RCX,  16
.set GREGS_RDX,  24
.set GREGS_RSI,  32
.set GREGS_RDI,  40
.set GREGS_RBP,  48
# GREGS_RSP = 56 - NOT loaded; CPU reads GUEST_RSP from the VMCS.
.set GREGS_R8,   64
.set GREGS_R9,   72
.set GREGS_R10,  80
.set GREGS_R11,  88
.set GREGS_R12,  96
.set GREGS_R13, 104
.set GREGS_R14, 112
.set GREGS_R15, 120
# GREGS_RIP    = 128 - NOT loaded; CPU reads GUEST_RIP from the VMCS.
# GREGS_RFLAGS = 136 - NOT loaded; CPU reads GUEST_RFLAGS from the VMCS.

.set VMEXIT_SAVE_SIZE, 120 


relm_vmentry_asm:
    #RDI : guest_regs pointer 
    #RSI : lanched flag 

    #save callee-saved registers to kthread stack 
    push    %rbp
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15

    mov     %rdi, %r12
    movl    %esi, %r13d 

    movq    %rsp, %rdi
    callq   relm_vmentry_save_rsp 

    movq    GREGS_RAX(%r12), %rax
    movq    GREGS_RBX(%r12), %rbx
    movq    GREGS_RCX(%r12), %rcx
    movq    GREGS_RDX(%r12), %rdx
    movq    GREGS_RSI(%r12), %rsi
    movq    GREGS_RBP(%r12), %rbp
    movq    GREGS_R8 (%r12), %r8
    movq    GREGS_R9 (%r12), %r9
    movq    GREGS_R10(%r12), %r10
    movq    GREGS_R11(%r12), %r11
    movq    GREGS_R14(%r12), %r14
    movq    GREGS_R15(%r12), %r15

    test %r13d, %r13d   

    movq    GREGS_RDI(%r12), %rdi
    movq    GREGS_R13(%r12), %r13
    movq    GREGS_R12(%r12), %rdi 

    jnz     do_resume

do_launch:
    vmlaunch
    jmp     vmx_error

do_resume:
    vmresume
    
vmx_error:
    movl    $-1, %eax  #return val 
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    pop     %rbp
    ret

#paths on handle_vmexit()
#1(continue) -> pop GPRs, vmresume
#0(stop) -> discard GPRs, retore kthread stak, return 0 to C loop 

relm_vmexit_handler:
    #CPU has already reloaded HOST_RSP from VMCS.
    # capture all Guest GPRs onto the Host stack.
    push    %rax
    push    %rbx
    push    %rcx
    push    %rdx
    push    %rsi
    push    %rdi
    push    %rbp
    push    %r8
    push    %r9
    push    %r10
    push    %r11
    push    %r12
    push    %r13
    push    %r14
    push    %r15 

    movq    %rsp, %rdi
    # align stack to 16 bytes for C ABI
    sub     $8, %rsp 
    call    handle_vmexit
    #restore alignment 
    add     $8, %rsp 

    testl   %eax, %eax
    jz      .Lvmexit_stop 

    #restore guest GPRs 
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rbp
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rbx
    pop     %rax

    vmresume
    
    addq    $VMEXIT_SAVE_SIZE, %rsp
    jmp     .Lvmexit_return_zero 

.Lvmexit_stop:
    addq    $VMEXIT_SAVE_SIZE, %rsp

.Lvmexit_return_zero:
    call    relm_vmentry_get_rsp
    testq   %rax, %rax 
    jz      .Lvmexit_fatal 

    movq    %rax, %rsp 
    xorl    %eax, %eax 

    pop     %r15                       # restore callee-saved (vmentry_asm step 1)
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    pop     %rbp
    ret                             # return 0 to relm_vcpu_loop
 
.Lvmexit_fatal:
    hlt
    jmp     .Lvmexit_fatal


