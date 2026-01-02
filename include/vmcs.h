#ifndef VMCS_H
#define VMCS_H

#include <linux/const.h>
#include "linux/kern_levels.h"
#include "vmcs_state.h"

#define X86_CR4_VMXE_BIT    13 
#define X86_CR4_VMXE        _BITUL(X86_CR4_VMXE_BIT)
#define MSR_IA32_VMX_MISC       0x00000485
#define VMCS_INSTRUCTION_ERROR_FIELD        0x00004400
/*enablling vmx through IA32_FEATURE_CONTROL_MSR */ 
#define IA32_FEATURE_CONTROL_LOCKED     (   1 << 0)
#define IA32_FEATURE_CONTROL_MSR_VMXON_ENABLE_OUTSIDE_SMX (1 << 2)
#define MSR_IA32_FEATURE_CONTROL            0x0000003A 


#define MSR_IA32_VMX_CR0_FIXED0             0x00000486 
#define MSR_IA32_VMX_CR0_FIXED1             0x00000487 
#define MSR_IA32_VMX_CR4_FIXED0             0x00000488 
#define MSR_IA32_VMX_CR4_FIXED1             0x00000489 

#define VMXON_REGION_PAGE_SIZE              4096 
#define VMCS_REGION_PAGE_SIZE               4096

/*------------- vm-execution control field ---------------*/ 

/*VMCS control field MSRs */ 

#define MSR_IA32_VMX_BASIC                  0x00000480 
#define MSR_IA32_VMX_PINBASED_CTLS          0x00000481 
#define MSR_IA32_VMX_PROCBASED_CTLS         0x00000482
#define MSR_IA32_VMX_EXIT_CTLS              0x00000483 
#define MSR_IA32_VMX_ENTRY_CTLS             0x00000484 
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x0000048B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x0000048C //EPT & VPID capabilities 
/*control field encodings  */  

#define VMCS_PIN_BASED_EXEC_CONTROLS                0x00004000 
#define VMCS_PRIMARY_PROC_BASED_EXEC_CONTROLS       0x00004002
#define VMCS_SECONDARY_PROC_BASED_EXEC_CONTROLS               0x0000401E 
#define VMCS_EXIT_CONTROLS                          0x0000400c
#define VMCS_ENTRY_CONTROLS                         0x00004012 

#define VM_EXIT_HOST_ADDR_SPACE_SIZE        0x00000200 
#define VM_ENTRY_IA32E_MODE                 0x00000200 
#define VMCS_INSTRUCTION_ERROR_FIELD        0x00004400 

#define VMCS_EXCEPTION_BITMAP               0x00004004

// =======================
// Pin-Based VMCS Controls
// =======================
#define VMCS_PIN_EXTINT_EXITING      (1u << 0)  // External Interrupt Exiting
#define VMCS_PIN_NMI_EXITING         (1u << 3)  // NMI Exiting
#define VMCS_PIN_VIRTUAL_NMIS        (1u << 5)  // Virtual NMIs
#define VMCS_PIN_PREEMPT_TIMER       (1u << 6)  // VMX Preemption Timer
#define VMCS_PIN_POSTED_INTRS        (1u << 7)  // Posted Interrupts (APICv)



// =======================
// Primary Processor-Based VMCS Controls (CTLS1)
// =======================
#define VMCS_PROC_USE_MSR_BITMAPS    (1u << 28) // Use MSR bitmaps
#define VMCS_PROC_ACTIVATE_SECONDARY (1u << 31) // Activate secondary controls
#define VMCS_PROC_HLT_EXITING        (1u << 7)  // VM-exit on HLT
#define VMCS_PROC_CR8_LOAD_EXITING   (1u << 19) // VM-exit on CR8 load
#define VMCS_PROC_CR8_STORE_EXITING  (1u << 20) // VM-exit on CR8 store
#define VMCS_PROC_TPR_SHADOW         (1u << 21) // Use TPR shadow
#define VMCS_PROC_UNCOND_IO_EXITING  (1u << 24) // Unconditional I/O exit
#define VMCS_PROC_USE_IO_BITMAPS     (1u << 25) // Use I/O bitmaps



// =======================
// Secondary Processor-Based VMCS Controls (CTLS2)
// =======================
#define VMCS_VPID                   (0X00000000)
#define VMCS_PROC2_ENABLE_EPT        (1u << 1)  // Enable EPT (Extended Page Tables)
#define VMCS_PROC2_RDTSCP            (1u << 3)  // RDTSCP instruction available to guest
#define VMCS_PROC2_VPID              (1u << 5)  // Enable VPID (Virtual Processor IDs)
#define VMCS_PROC2_UNRESTRICTED_GUEST (1u << 7) // Unrestricted guest (real mode allowed)
#define VMCS_PROC2_ENABLE_VMFUNC     (1u << 13) // Enable VMFUNC instruction



// =======================
// VM-Entry VMCS Controls
// =======================
#define VMCS_ENTRY_LOAD_GUEST_PAT    (1u << 14) // Load guest PAT on VM-entry
#define VMCS_ENTRY_LOAD_IA32_EFER    (1u << 15) // Load guest IA32_EFER on VM-entry
#define VMCS_ENTRY_LOAD_DEBUG         (1u << 2)  // Load debug controls on VM-entry

// =======================
// VM-Exit VMCS Controls
// =======================
#define VMCS_EXIT_SAVE_IA32_PAT      (1u << 4)  // Save guest PAT on VM-exit
#define VMCS_EXIT_LOAD_IA32_PAT      (1u << 5)  // Load host PAT on VM-exit
#define VMCS_EXIT_SAVE_EFER          (1u << 9)  // Save guest IA32_EFER on VM-exit
#define VMCS_EXIT_LOAD_EFER          (1u << 10) // Load host IA32_EFER on VM-exit
#define VMCS_EXIT_ACK_INTR_ON_EXIT   (1u << 15) // Acknowledge external interrupts on VM-exit
/* for checking bit 28 of procbased control if msr bitmaps is enabled (bit 28 = 1) */ 

#define VMCS_MSR_BITMAPS_BIT                 28 

/*msr vitmap field in the VMCS */ 

#define VMCS_MSR_BITMAP                     0x00002004

#define VMCS_IO_BITMAP_A                    0x00002000 
#define VMCS_IO_BITMAP_B                    0x00002002 

#define VMCS_IO_BITMAP_PAGE_SIZE             4096
#define VMCS_IO_BITMAP_PAGES_ORDER           1 
#define VMCS_IO_BITMAP_SIZE                  (VMCS_IO_BITMAP_PAGE_SIZE << VMCS_IO_BITMAP_PAGES_ORDER)

/* CR0 bits */
#define X86_CR0_PE                          0x00000001 /* Protected Mode */
#define X86_CR0_NE                          0x00000020 /* Numeric Error */
#define X86_CR0_NW                          0x20000000 /* Not Write-through */
#define X86_CR0_CD                          0x40000000 /* Cache Disable */
#define X86_CR0_PG                          0x80000000 /* Paging */

/* CR4 bits */
#define X86_CR4_PSE                         0x00000010 /* Page Size Extensions */
#define X86_CR4_PAE                         0x00000020 /* Physical Address Extension */
#define X86_CR4_VMXE                        0x00002000 /* VMX Enable */ 

#define GUEST_CR0                           0x00006800
#define GUEST_CR3                           0x00006802
#define GUEST_CR4                           0x00006804

#define CR0_GUEST_HOST_MASK            0x00006004
#define CR0_READ_SHADOW                0x00006006
#define CR4_GUEST_HOST_MASK            0x00006008
#define CR4_READ_SHADOW                0x0000600A

/* VMCS field encodings for CR3 targets */ 

#define VMCS_CR3_TARGET_VALUE0              0x0000600C
#define VMCS_CR3_TARGET_VALUE1              0x0000600E
#define VMCS_CR3_TARGET_VALUE2              0x00006010
#define VMCS_CR3_TARGET_VALUE3              0x00006012

/*for storing MSRs on vm exit */

#define MSR_AREA_ENTRIES                    1 
#define VM_EXIT_MSR_STORE_COUNT             0x00002004 
#define VM_EXIT_MSR_STORE_ADDR              0x00002006
#define VM_ENTRY_MSR_LOAD_COUNT             0x00002008 
#define VM_ENTRY_MSR_LOAD_ADDR              0x0000200A

#define IA32_SYSENTER_CS                    0x00000174

/* * CR3-Target Count (32-bit Control Field) 
 */
#define CR3_TARGET_COUNT                    0x0000400A

/* * CR3-Target Values (Natural-Width Control Fields)  */
#define CR3_TARGET_VALUE0                   0x00006008
#define CR3_TARGET_VALUE1                   0x0000600A
#define CR3_TARGET_VALUE2                   0x0000600C
#define CR3_TARGET_VALUE3                   0x0000600E


#define MSR_IA32_EFER      0xC0000080
#define MSR_IA32_STAR      0xC0000081
#define MSR_IA32_LSTAR     0xC0000082
#define MSR_IA32_CSTAR     0xC0000083
#define MSR_IA32_FMASK     0xC0000084

#define MSR_IA32_FS_BASE   0xC0000100
#define MSR_IA32_GS_BASE   0xC000010

struct vmcs{
    u32 revision_id;
    u32 abort;
    char data[0]
}__aligned(PAGE_SIZE); 

struct vmxon_region{
    u32 revision_id; 
    u32 reserved; 
    char data[0]; 
}__aligned(PAGE_SIZE); 

struct vmx_exec_ctrls{
    uint32_t pin_based;
    uint32_t primary_proc;
    uint32_t secondary_proc; 
    uint32_t vm_entry; 
    uint32_t vm_exit; 
};

struct _msr_entry 
{
    uint32_t index; 
    uint32_t reserved; 
    uint64_t value; 
}__attribute__ ((packed, aligned(16))); 

const uint32_t kvx_vmexit_msr_indices[] = {
    MSR_IA32_EFER,
    MSR_IA32_STAR,
    MSR_IA32_LSTAR,
    MSR_IA32_CSTAR,
    MSR_IA32_FMASK,
    MSR_IA32_FS_BASE,
    MSR_IA32_GS_BASE
};

#define KVX_VMEXIT_MSR_COUNT \ 
    ARRAY_SIZE(kvx_vmexit_msr_indices)

const uint32_t kvx_vmentry_msr_indices[] = {
    MSR_IA32_EFER,
    MSR_IA32_STAR,
    MSR_IA32_LSTAR,
    MSR_IA32_CSTAR,
    MSR_IA32_FMASK,
    MSR_IA32_FS_BASE,
    MSR_IA32_GS_BASE
};

#define KVX_VMENTRY_MSR_COUNT \
    ARRAY_SIZE(kvx_vmentry_msr_indices)

uint64_t kvx_vmentry_msr_values[KVX_VMENTRY_MSR_COUNT]; 

#endif 
