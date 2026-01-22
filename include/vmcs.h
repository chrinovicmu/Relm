#ifndef VMCS_H
#define VMCS_H

#include <linux/const.h>
#include <linux/kern_levels.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <include/vmcs_state.h>

/* VMX Basic Constants */
#define X86_CR4_VMXE_BIT      13
#define VMXON_REGION_PAGE_SIZE 4096 
#define VMCS_REGION_PAGE_SIZE  4096

/* IA32_FEATURE_CONTROL MSR bits */
#define MSR_IA32_FEATURE_CONTROL                          0x0000003A 
#define IA32_FEATURE_CONTROL_LOCKED                       (1 << 0)
#define IA32_FEATURE_CONTROL_MSR_VMXON_ENABLE_OUTSIDE_SMX (1 << 2)

/* * VMCS Field Encodings
 * These are the hex codes used with __vmread() and __vmwrite()
 */

/* 16-bit Control Fields */
#define VMCS_VPID                             0x00000000

/* 64-bit Control Fields */
#define VMCS_IO_BITMAP_A                      0x00002000 
#define VMCS_IO_BITMAP_B                      0x00002002 
#define VMCS_MSR_BITMAP                       0x00002004
#define VMCS_EXIT_MSR_STORE_ADDR              0x00002006
#define VMCS_EXIT_MSR_LOAD_ADDR               0x00002008
#define VMCS_ENTRY_MSR_LOAD_ADDR              0x0000200a

/* 32-bit Control Fields */
#define VMCS_PIN_BASED_EXEC_CONTROLS          0x00004000 
#define VMCS_PRIMARY_PROC_BASED_EXEC_CONTROLS 0x00004002
#define VMCS_EXCEPTION_BITMAP                 0x00004004
#define VMCS_EXIT_CONTROLS                    0x0000400c
#define VMCS_EXIT_MSR_STORE_COUNT             0x00002007
#define VMCS_EXIT_MSR_LOAD_COUNT              0x00002009
#define VMCS_ENTRY_CONTROLS                   0x00004012 
#define VMCS_ENTRY_MSR_LOAD_COUNT             0x0000200b
#define VMCS_SECONDARY_PROC_BASED_EXEC_CONTROLS 0x0000401E 
#define VMCS_INSTRUCTION_ERROR_FIELD          0x00004400 

/* Natural-Width Control Fields */
#define CR0_GUEST_HOST_MASK                   0x00006000
#define CR4_GUEST_HOST_MASK                   0x00006002
#define CR0_READ_SHADOW                       0x00006004
#define CR4_READ_SHADOW                       0x00006006
#define CR3_TARGET_COUNT                      0x0000400A
#define CR3_TARGET_VALUE0                     0x00006008
#define CR3_TARGET_VALUE1                     0x0000600A
#define CR3_TARGET_VALUE2                     0x0000600C
#define CR3_TARGET_VALUE3                     0x0000600E

/* Guest State Fields */
#define GUEST_CR0                             0x00006800
#define GUEST_CR3                             0x00006802
#define GUEST_CR4                             0x00006804
#define GUEST_RIP                             0x0000681E
#define GUEST_RSP                             0x0000681C
#define GUEST_RFLAGS                          0x00006820

/* =======================
 * Pin-Based VMCS Controls
 * ======================= */
#define VMCS_PIN_EXTINT_EXITING      (1u << 0)
#define VMCS_PIN_NMI_EXITING         (1u << 3)
#define VMCS_PIN_VIRTUAL_NMIS        (1u << 5)
#define VMCS_PIN_PREEMPT_TIMER       (1u << 6)
#define VMCS_PIN_POSTED_INTRS        (1u << 7)

/* =======================
 * Primary Processor-Based Controls
 * ======================= */
#define VMCS_PROC_HLT_EXITING        (1u << 7)
#define VMCS_PROC_CR8_LOAD_EXITING   (1u << 19)
#define VMCS_PROC_CR8_STORE_EXITING  (1u << 20)
#define VMCS_PROC_TPR_SHADOW         (1u << 21)
#define VMCS_PROC_UNCOND_IO_EXITING  (1u << 24)
#define VMCS_PROC_USE_IO_BITMAPS     (1u << 25)
#define VMCS_PROC_USE_MSR_BITMAPS    (1u << 28)
#define VMCS_PROC_ACTIVATE_SECONDARY (1u << 31)

/* =======================
 * Secondary Processor-Based Controls
 * ======================= */
#define VMCS_PROC2_ENABLE_EPT         (1u << 1)
#define VMCS_PROC2_RDTSCP             (1u << 3)
#define VMCS_PROC2_VPID               (1u << 5)
#define VMCS_PROC2_UNRESTRICTED_GUEST (1u << 7)
#define VMCS_PROC2_ENABLE_VMFUNC      (1u << 13)

/* =======================
 * VM-Exit Controls
 * ======================= */
#define VM_EXIT_HOST_ADDR_SPACE_SIZE (1u << 9)
#define VMCS_EXIT_SAVE_IA32_PAT      (1u << 18)
#define VMCS_EXIT_LOAD_IA32_PAT      (1u << 19)
#define VMCS_EXIT_SAVE_EFER          (1u << 20)
#define VMCS_EXIT_LOAD_EFER          (1u << 21)
#define VMCS_EXIT_ACK_INTR_ON_EXIT   (1u << 15)

/* =======================
 * VM-Entry Controls
 * ======================= */
#define VM_ENTRY_IA32E_MODE          (1u << 9)
#define VMCS_ENTRY_LOAD_DEBUG        (1u << 2)
#define VMCS_ENTRY_LOAD_GUEST_PAT    (1u << 14)
#define VMCS_ENTRY_LOAD_IA32_EFER    (1u << 15)

/* MSR Constants and Fixes */
#define MSR_IA32_EFER       0xC0000080
#define MSR_IA32_STAR       0xC0000081
#define MSR_IA32_LSTAR      0xC0000082
#define MSR_IA32_CSTAR      0xC0000083
#define MSR_IA32_FMASK      0xC0000084
#define MSR_IA32_FS_BASE    0xC0000100
#define MSR_IA32_GS_BASE    0xC0000101  
#define IA32_SYSENTER_CS    0x00000174

/* Memory Management Constants */
#define VMCS_IO_BITMAP_PAGE_SIZE    4096
#define VMCS_IO_BITMAP_PAGES_ORDER  1 
#define VMCS_IO_BITMAP_SIZE         (VMCS_IO_BITMAP_PAGE_SIZE << VMCS_IO_BITMAP_PAGES_ORDER)

/* Struct Definitions */
struct vmcs_region {
    u32 revision_id;
    u32 abort;
    char data[0];
} __aligned(PAGE_SIZE); 

struct vmxon_region {
    u32 revision_id; 
    u32 reserved; 
    char data[0]; 
} __aligned(PAGE_SIZE); 

struct vmx_exec_ctrls {
    uint32_t pin_based;
    uint32_t primary_proc;
    uint32_t secondary_proc; 
    uint32_t vm_entry; 
    uint32_t vm_exit; 
};

struct msr_entry 
{
    uint32_t index; 
    uint32_t reserved; 
    uint64_t value; 
} __attribute__ ((packed, aligned(16))); 

/* Externs and Counts */
extern const uint32_t relm_vmexit_msr_indices[];
extern const uint32_t relm_vmentry_msr_indices[];
extern uint64_t relm_vmentry_msr_values[];

#define RELM_VMEXIT_MSR_COUNT 7
#define RELM_VMENTRY_MSR_COUNT 7

#endif
