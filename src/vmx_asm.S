
#vm_lanucher.s 
#
#this file contains the vmx transition code. 
#it is reposible for: 
#   - loading guest gneral purpost registers 
#   - executing VM-entry (VMLAUNCH / VMRESUME)
#   - regainning control on VM-exit 

# This code runs in kernel mode, with interrupts disabled or controlled,
# and must obey the System V AMD64 ABI where applicable.

.globl kvx_vmentry_asm 
.globl kvx_vmexit_handler 
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


kvx_vmentry_asm:
    #RDI : guest_regs pointer 
    #RSI : lanched flag 

    mov %rsi, %r10 

    push %rbp
    push %rdi

    mov VCPU_RAX(%rdi), %rax 
    mov VCPU_RBX(%rdi), %rbx
    mov VCPU_RCX(%rdi), %rcx
    mov VCPU_RDX(%rdi), %rdx
    mov VCPU_RSI(%rdi), %rsi
    mov VCPU_RBP(%rdi), %rbp
    mov VCPU_R8(%rdi),  %r8
    mov VCPU_R9(%rdi),  %r9

    /*skip r10 for now, as it contains launcher condition */ 
    mov VCPU_R11(%rdi), %r11
    mov VCPU_R12(%rdi), %r12
    mov VCPU_R13(%rdi), %r13
    mov VCPU_R14(%rdi), %r14
    mov VCPU_R15(%rdi), %r15

    /*check launched flag before overwrite */ 
    test %r10, %r10 
    mov VCPU_R10(%rdi), %r10 

    mov VCPU_RDI(%rdi), %rdi 

    jnz do_resume

do_launch:
    vmlaunch
    jmp vmx_error

do_resume:
    vmresume
    jmp vmx_error
    
vmx_error:
    pop %rbp 
    ret 


kvx_vmexit_handler:
    #CPU has already reloaded HOST_RSP from VMCS.
    # capture all Guest GPRs onto the Host stack.
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15 

    mov %rsp, %rdi
    # align stack to 16 bytes for C ABI
    sub $8, %rsp 
    call handle_vmexit

    #cleanup alignment 
    add $8, %rsp 

    #restore guest GPRs 
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax

    vmresume

vmx_error:
    pop %rdi
    pop %rbp 
    mov $-1, %rax 
    ret 
