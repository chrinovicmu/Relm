
#ifndef LKM_HYP_H 
#define LKM_HYP_H

#include <linux/const.h>
#include "linux/kern_levels.h"
#include "vmcs_state.h"

#define X86_CR4_VMXE_BIT    13 
#define X86_CR4_VMXE        _BITUL(X86_CR4_VMXE_BIT)


/*enablling vmx through IA32_FEATURE_CONTROL_MSR */ 
#define IA32_FEATURE_CONTROL_LOCKED     (   1 << 0)
#define IA32_FEATURE_CONTROL_MSR_VMXON_ENABLE_OUTSIDE_SMX (1 << 2)
#define MSR_IA32_FEATURE_CONTROL            0x0000003A 


#define MSR_IA32_VMX_CR0_FIXED0             0x00000486 
#define MSR_IA32_VMX_CR0_FIXED1             0x00000487 
#define MSR_IA32_VMX_CR4_FIXED0             0x00000488 
#define MSR_IA32_VMX_CR4_FIXED1             0x00000489 

/*revison idenfiier */ 

#define MSR_IA32_VMX_BASIC                  0x00000480 

#define VMXON_REGION_PAGE_SIZE              4096 
#define VMCS_REGION_PAGE_SIZE               4096


/*------------- vm-execution control field ---------------*/ 

/*VMCS control field MSRs */ 

#define MSR_IA32_VMX_PINBASED_CTLS          0x00000481 
#define MSR_IA32_VMX_PROCBASED_CTLS         0x00000482
#define MSR_IA32_VMX_EXIT_CTLS              0x00000483 
#define MSR_IA32_VMX_ENTRY_CTLS             0x00000484 

/*control field encodings  */  

#define VMCS_PIN_BASED_EXEC_CONTROLS        0x00004000 
#define VMCS_PROC_BASED_EXEC_CONTROLS       0x00004002 
#define VMCS_EXIT_CONTROLS                  0x0000400c 
#define VMCS_ENTRY_CONTROLS                 0x00004012 
#define VM_EXIT_HOST_ADDR_SPACE_SIZE        0x00000200 
#define VM_ENTRY_IA32E_MODE                 0x00000200 
#define VMCS_INSTRUCTION_ERROR_FIELD        0x00004400 

#define VMCS_EXCEPTION_BITMAP               0x00004004

/* for checking bit 28 of procbased control if msr bitmaps is enabled (bit 28 = 1) */ 

#define VMCS_MSR_BITMAPS_BIT                 28 

/*msr vitmap field in the VMCS */ 

#define VMCS_MSR_BITMAP                     0x00002004

#define VMCS_IO_BITMAP_A                    0x00002000 
#define VMCS_IO_BITMAP_B                    0x00002002 

#define VMCS_IO_BITMAP_PAGE_SIZE             4096
#define VMCS_IO_BITMAP_PAGES_ORDER           1 
#define VMCS_IO_BITMAP_SIZE                  (VMCS_IO_BITMAP_PAGE_SIZE << VMCS_IO_BITMAP_PAGES_ORDER)

#define VMCS_CR0_GUEST_HOST_MASK            0x00006004
#define VMCS_CR0_READ_SHADOW                0x00006006
#define VMCS_CR4_GUEST_HOST_MASK            0x00006008
#define VMCS_CR4_READ_SHADOW                0x0000600A

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

/*memory regions */

uint64_t *vmxon_region = NULL; 
uint64_t *vmcs_region  = NULL; 

uint8_t *io_bitmap; 
void * msr_bitmap; 


#endif 
