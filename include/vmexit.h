#ifndef VMEXIT_H
#define VMEXIT_H

#include <vm.h> 
#include <vmcs_state.h>
#include <vmx.h>
#include <vmx_ops.h>
#include <utils.h> 

#define VM_EXIT_REASON                          0x00004402
#define VM_EXIT_QUALIFICATION                   0x00006400
#define VM_EXIT_INSTRUCTION_LEN                 0x0000440c
#define VM_EXIT_INTR_INFO	                    0x00004404
#define VM_EXIT_INTR_ERROR_CODE             	0x00004406

#define EXIT_REASON_EXCEPTION_NMI               0x00000000
#define EXIT_REASON_EXTERNAL_INTERRUPT          0x00000001
#define EXIT_REASON_TRIPLE_FAULT                0x00000002
#define EXIT_REASON_INIT_SIGNAL                 0x00000003
#define EXIT_REASON_SIPI                        0x00000004
#define EXIT_REASON_IO_SMI                      0x00000005
#define EXIT_REASON_OTHER_SMI                   0x00000006
#define EXIT_REASON_PENDING_VIRT_INTR           0x00000007
#define EXIT_REASON_PENDING_VIRT_NMI            0x00000008
#define EXIT_REASON_TASK_SWITCH                 0x00000009
#define EXIT_REASON_CPUID                       0x0000000A
#define EXIT_REASON_GETSEC                      0x0000000B
#define EXIT_REASON_HLT                         0x0000000C
#define EXIT_REASON_INVD                        0x0000000D
#define EXIT_REASON_INVLPG                      0x0000000E
#define EXIT_REASON_RDPMC                       0x0000000F
#define EXIT_REASON_RDTSC                       0x00000010
#define EXIT_REASON_RSM                         0x00000011
#define EXIT_REASON_VMCALL                      0x00000012
#define EXIT_REASON_VMCLEAR                     0x00000013
#define EXIT_REASON_VMLAUNCH                    0x00000014
#define EXIT_REASON_VMPTRLD                     0x00000015
#define EXIT_REASON_VMPTRST                     0x00000016
#define EXIT_REASON_VMREAD                      0x00000017
#define EXIT_REASON_VMRESUME                    0x00000018
#define EXIT_REASON_VMWRITE                     0x00000019
#define EXIT_REASON_VMXOFF                      0x0000001A
#define EXIT_REASON_VMXON                       0x0000001B
#define EXIT_REASON_CR_ACCESS                   0x0000001C
#define EXIT_REASON_DR_ACCESS                   0x0000001D
#define EXIT_REASON_IO_INSTRUCTION              0x0000001E
#define EXIT_REASON_MSR_READ                    0x0000001F
#define EXIT_REASON_MSR_WRITE                   0x00000020
#define EXIT_REASON_INVALID_GUEST_STATE         0x00000021
#define EXIT_REASON_MSR_LOADING                 0x00000022
#define EXIT_REASON_MWAIT_INSTRUCTION           0x00000024
#define EXIT_REASON_MONITOR_TRAP_FLAG           0x00000025
#define EXIT_REASON_MONITOR_INSTRUCTION         0x00000027
#define EXIT_REASON_PAUSE_INSTRUCTION           0x00000028
#define EXIT_REASON_MCE_DURING_VMENTRY          0x00000029
#define EXIT_REASON_TPR_BELOW_THRESHOLD         0x0000002B
#define EXIT_REASON_APIC_ACCESS                 0x0000002C
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR         0x0000002E
#define EXIT_REASON_ACCESS_LDTR_OR_TR           0x0000002F
#define EXIT_REASON_EPT_VIOLATION               0x00000030
#define EXIT_REASON_EPT_MISCONFIG               0x00000031
#define EXIT_REASON_INVEPT                      0x00000032
#define EXIT_REASON_RDTSCP                      0x00000033
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 0x00000034
#define EXIT_REASON_INVVPID                     0x00000035
#define EXIT_REASON_WBINVD                      0x00000036
#define EXIT_REASON_XSETBV                      0x00000037
#define EXIT_REASON_APIC_WRITE                  0x00000038
#define EXIT_REASON_RDRAND                      0x00000039
#define EXIT_REASON_INVPCID                     0x0000003A
#define EXIT_REASON_RDSEED                      0x0000003D
#define EXIT_REASON_PML_FULL                    0x0000003E
#define EXIT_REASON_XSAVES                      0x0000003F
#define EXIT_REASON_XRSTORS                     0x00000040
#define EXIT_REASON_PCOMMIT                     0x00000041

extern struct vcpu *relm_get_current_vcpu(void);

struct stack_guest_gprs {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbp;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;
} __attribute__((packed));

int handle_vmexit(struct stack_guest_gprs *guest_gprs);

#endif
