.intel_syntax noprefix
.code64

.global _start
_start:

    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor rsi, rsi
    xor rdi, rdi
    xor r8,  r8
    xor r9,  r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    mov r12, 0x4142434445464748
    push r12
    pop r12

    mov rax, 0xDEADBEEFCAFEBABE
    mov QWORD PTR [0x2000], rax
    mov rbx, QWORD PTR [0x2000]
    sub rbx, rax

    hlt
